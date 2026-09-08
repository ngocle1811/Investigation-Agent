"""Source-aware chunking strategies for the four knowledge source types."""

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from investigation_agent.ingestion.enrich import contextualize
from investigation_agent.ingestion.schemas import KnowledgeChunk, KnowledgeDocument
from investigation_agent.ingestion.utils import normalize_text, sha256_text

_SYSMON_EVENT = re.compile(r"^Event ID\s+(\d+)\s*:\s*(.+)$", re.IGNORECASE)


def deterministic_chunk_id(
    document_id: str, *, role: str, section: str, content_hash: str
) -> str:
    """Create a stable chunk identifier from logical identity and exact content."""

    identity = json.dumps(
        [document_id, role, section, content_hash], ensure_ascii=False, separators=(",", ":")
    )
    return f"chk-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"


def _document_metadata(document: KnowledgeDocument) -> dict[str, Any]:
    """Preserve document metadata without duplicating the full section tree per point."""

    return {key: value for key, value in document.metadata.items() if key != "sections"}


def _build_chunk(
    document: KnowledgeDocument,
    *,
    role: str,
    section: str,
    content: str,
    parent_id: str | None = None,
    title: str | None = None,
    event_id: int | None = None,
    technique_id: str | None = None,
    tactic: str | None = None,
    retrieval_enabled: bool = True,
    metadata: dict[str, Any] | None = None,
) -> KnowledgeChunk:
    """Build one validated chunk and its deterministic contextual prepend."""

    content = normalize_text(content)
    content_hash = sha256_text(content)
    chunk_id = deterministic_chunk_id(
        document.document_id, role=role, section=section, content_hash=content_hash
    )
    merged_metadata = _document_metadata(document)
    merged_metadata.update(metadata or {})
    return KnowledgeChunk(
        chunk_id=chunk_id,
        document_id=document.document_id,
        parent_id=parent_id,
        source=document.source,
        source_type=document.source_type,
        title=title or document.title,
        section=section,
        content=content,
        contextualized_content=contextualize(
            document,
            section=section,
            content=content,
            technique_id=technique_id,
            tactic=tactic,
            event_id=event_id,
        ),
        url=document.url,
        version=document.version,
        effective_or_modified_date=document.effective_or_modified_date,
        event_id=event_id if event_id is not None else document.event_id,
        sigma_rule_id=document.sigma_rule_id,
        technique_id=technique_id,
        tactic=tactic,
        content_hash=content_hash,
        retrieval_enabled=retrieval_enabled,
        metadata=merged_metadata,
    )


def _sections(document: KnowledgeDocument) -> list[dict[str, Any]]:
    """Validate the normalized section metadata used by HTML chunkers."""

    raw_sections = document.metadata.get("sections", [])
    if not isinstance(raw_sections, list):
        raise ValueError(f"Document {document.document_id} has invalid section metadata")
    sections = []
    for section in raw_sections:
        if (
            not isinstance(section, dict)
            or not section.get("heading")
            or not section.get("content")
        ):
            continue
        sections.append(
            {
                "heading": str(section["heading"]),
                "level": int(section.get("level", 2)),
                "content": str(section["content"]),
            }
        )
    return sections


def _parent_chunk(document: KnowledgeDocument) -> KnowledgeChunk:
    """Build a stored parent context that dense search excludes by default."""

    return _build_chunk(
        document,
        role="parent",
        section="Full document",
        content=document.content,
        retrieval_enabled=False,
        metadata={"chunk_role": "parent"},
    )


def chunk_microsoft(document: KnowledgeDocument) -> list[KnowledgeChunk]:
    """Create a document parent plus children at Windows documentation boundaries."""

    parent = _parent_chunk(document)
    sections = _sections(document) or [
        {"heading": "Document", "level": 2, "content": document.content}
    ]
    children = [
        _build_chunk(
            document,
            role="section",
            section=section["heading"],
            content=section["content"],
            parent_id=parent.chunk_id,
            title=f"{document.title} — {section['heading']}",
            metadata={"chunk_role": "child", "heading_level": section["level"]},
        )
        for section in sections
    ]
    return [parent, *children]


def _sysmon_groups(document: KnowledgeDocument) -> list[dict[str, Any]]:
    """Group each Sysmon event heading with its subordinate logical sections."""

    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for section in _sections(document):
        match = _SYSMON_EVENT.match(section["heading"])
        if match:
            if current:
                groups.append(current)
            current = {
                "heading": section["heading"],
                "level": section["level"],
                "event_id": int(match.group(1)),
                "event_name": match.group(2).strip(),
                "parts": [section["content"]],
            }
            continue
        if current and section["level"] > current["level"]:
            current["parts"].append(f"{section['heading']}\n{section['content']}")
            continue
        if current:
            groups.append(current)
            current = None
        groups.append(
            {
                "heading": section["heading"],
                "level": section["level"],
                "event_id": None,
                "event_name": None,
                "parts": [section["content"]],
            }
        )
    if current:
        groups.append(current)
    return groups


def chunk_sysmon(document: KnowledgeDocument) -> list[KnowledgeChunk]:
    """Create a parent plus event-level and other logical Sysmon section chunks."""

    parent = _parent_chunk(document)
    groups = _sysmon_groups(document) or [
        {
            "heading": "Document",
            "level": 2,
            "event_id": None,
            "event_name": None,
            "parts": [document.content],
        }
    ]
    children = []
    for group in groups:
        event_id = group["event_id"]
        metadata = {"chunk_role": "child", "heading_level": group["level"]}
        if event_id is not None:
            metadata.update(
                {"sysmon_event_id": event_id, "sysmon_event_name": group["event_name"]}
            )
        children.append(
            _build_chunk(
                document,
                role="sysmon_event" if event_id is not None else "section",
                section=group["heading"],
                content="\n\n".join(group["parts"]),
                parent_id=parent.chunk_id,
                title=f"{document.title} — {group['heading']}",
                event_id=event_id,
                metadata=metadata,
            )
        )
    return [parent, *children]


def chunk_sigma(document: KnowledgeDocument) -> list[KnowledgeChunk]:
    """Keep one complete Sigma rule as one retrievable chunk."""

    return [
        _build_chunk(
            document,
            role="sigma_rule",
            section="Rule",
            content=document.content,
            metadata={"chunk_role": "rule"},
        )
    ]


def chunk_mitre(document: KnowledgeDocument) -> list[KnowledgeChunk]:
    """Keep one ATT&CK technique/sub-technique while preserving its hierarchy."""

    actual_technique_id = document.subtechnique_id or document.technique_id
    tactics = document.metadata.get("tactics") or []
    tactic = str(tactics[0]) if tactics else None
    is_subtechnique = bool(document.subtechnique_id)
    return [
        _build_chunk(
            document,
            role="mitre_subtechnique" if is_subtechnique else "mitre_technique",
            section="Sub-technique" if is_subtechnique else "Technique",
            content=document.content,
            technique_id=actual_technique_id,
            tactic=tactic,
            metadata={
                "chunk_role": "subtechnique" if is_subtechnique else "technique",
                "parent_technique_id": document.technique_id if is_subtechnique else None,
            },
        )
    ]


_CHUNKERS: dict[str, Callable[[KnowledgeDocument], list[KnowledgeChunk]]] = {
    "windows_event_doc": chunk_microsoft,
    "sysmon_doc": chunk_sysmon,
    "sigma_rule": chunk_sigma,
    "mitre_attack": chunk_mitre,
}


def chunk_document(document: KnowledgeDocument) -> list[KnowledgeChunk]:
    """Dispatch to the only chunking strategy valid for the document's source type."""

    try:
        chunker = _CHUNKERS[document.source_type]
    except KeyError as exc:
        raise ValueError(f"No chunker for source type {document.source_type}") from exc
    return chunker(document)


def chunk_documents(documents: list[KnowledgeDocument]) -> list[KnowledgeChunk]:
    """Chunk documents deterministically and reject any identifier collision."""

    chunks = [chunk for document in documents for chunk in chunk_document(document)]
    chunks.sort(key=lambda chunk: (chunk.source_type, chunk.document_id, chunk.chunk_id))
    chunk_ids = [chunk.chunk_id for chunk in chunks]
    if len(chunk_ids) != len(set(chunk_ids)):
        raise ValueError("Deterministic chunk ID collision detected")
    return chunks

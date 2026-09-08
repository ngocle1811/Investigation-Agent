"""Checkpoint 1 download, normalize, deduplicate, and JSONL preparation pipeline."""

import json
from collections import Counter
from pathlib import Path

import yaml

from investigation_agent.ingestion.fetch import RawStore
from investigation_agent.ingestion.microsoft import normalize_microsoft_document
from investigation_agent.ingestion.mitre import normalize_mitre_bundle
from investigation_agent.ingestion.schemas import (
    IngestionSummary,
    KnowledgeDocument,
    SourcesConfig,
)
from investigation_agent.ingestion.sigma import normalize_sigma_rule
from investigation_agent.ingestion.sysmon import normalize_sysmon_document
from investigation_agent.ingestion.utils import atomic_write_bytes


def load_sources_config(path: Path) -> SourcesConfig:
    """Load and strictly validate the curated source configuration."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return SourcesConfig.model_validate(payload)


def _portable(document: KnowledgeDocument, project_root: Path) -> KnowledgeDocument:
    """Store a project-relative raw path in generated documents."""

    raw_path = Path(document.raw_path)
    try:
        portable_path = raw_path.relative_to(project_root).as_posix()
    except ValueError:
        portable_path = raw_path.as_posix()
    return document.model_copy(update={"raw_path": portable_path})


def _load_previous(path: Path) -> dict[str, KnowledgeDocument]:
    """Load the previous valid output for idempotency statistics."""

    if not path.exists():
        return {}
    documents: dict[str, KnowledgeDocument] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            document = KnowledgeDocument.model_validate_json(line)
        except ValueError as exc:
            raise ValueError(f"Invalid existing JSONL at line {line_number}") from exc
        documents[document.document_id] = document
    return documents


def _serialize_jsonl(documents: list[KnowledgeDocument]) -> bytes:
    """Serialize normalized documents in stable order."""

    lines = [document.model_dump_json(exclude_none=False) for document in documents]
    return ("\n".join(lines) + "\n").encode("utf-8")


def prepare_knowledge(
    *,
    project_root: Path,
    config_path: Path | None = None,
    output_path: Path | None = None,
    refresh: bool = False,
    offline: bool = False,
) -> IngestionSummary:
    """Prepare normalized knowledge JSONL from the four curated source families."""

    project_root = project_root.resolve()
    config_path = (config_path or project_root / "config" / "sources.yaml").resolve()
    output_path = (
        output_path or project_root / "data" / "processed" / "knowledge" / "documents.jsonl"
    ).resolve()
    config = load_sources_config(config_path)
    documents: list[KnowledgeDocument] = []

    with RawStore(project_root / "data" / "raw") as raw_store:
        for entry in config.microsoft_pages:
            if not entry.enabled:
                continue
            artifact = raw_store.fetch(
                entry,
                source="microsoft",
                directory="microsoft",
                refresh=refresh,
                offline=offline,
            )
            documents.append(normalize_microsoft_document(artifact, entry))

        for entry in config.sysmon_pages:
            if not entry.enabled:
                continue
            artifact = raw_store.fetch(
                entry,
                source="microsoft",
                directory="sysmon",
                refresh=refresh,
                offline=offline,
            )
            documents.append(normalize_sysmon_document(artifact, entry))

        for entry in config.sigma_rules:
            if not entry.enabled:
                continue
            artifact = raw_store.fetch(
                entry,
                source="sigma",
                directory="sigma",
                refresh=refresh,
                offline=offline,
            )
            documents.append(normalize_sigma_rule(artifact, entry))

        if config.mitre_attack.enabled:
            artifact = raw_store.fetch(
                config.mitre_attack,
                source="mitre_attack",
                directory="mitre",
                refresh=refresh,
                offline=offline,
            )
            documents.extend(normalize_mitre_bundle(artifact, config.mitre_attack))

    documents = sorted(
        (_portable(document, project_root) for document in documents),
        key=lambda document: (document.source, document.document_id),
    )
    document_ids = [document.document_id for document in documents]
    duplicates = sorted(
        document_id for document_id, count in Counter(document_ids).items() if count > 1
    )
    if duplicates:
        raise ValueError(f"Duplicate normalized document IDs: {duplicates}")

    previous = _load_previous(output_path)
    added = sum(document.document_id not in previous for document in documents)
    updated = sum(
        document.document_id in previous
        and previous[document.document_id].content_hash != document.content_hash
        for document in documents
    )
    unchanged = len(documents) - added - updated
    serialized = _serialize_jsonl(documents)
    output_changed = not output_path.exists() or output_path.read_bytes() != serialized
    if output_changed:
        atomic_write_bytes(output_path, serialized)

    by_source = dict(sorted(Counter(document.source for document in documents).items()))
    return IngestionSummary(
        output_path=output_path.relative_to(project_root).as_posix(),
        documents=len(documents),
        by_source=by_source,
        added=added,
        updated=updated,
        unchanged=unchanged,
        output_changed=output_changed,
    )


def summary_as_json(summary: IngestionSummary) -> str:
    """Render a stable human-readable CLI summary."""

    return json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2)

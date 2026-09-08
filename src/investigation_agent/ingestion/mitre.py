"""MITRE ATT&CK Enterprise STIX normalization."""

import json
from typing import Any

from investigation_agent.ingestion.schemas import KnowledgeDocument, RawArtifact, SourceEntry
from investigation_agent.ingestion.utils import normalize_text, sha256_text


def _external_id(item: dict[str, Any]) -> str | None:
    """Extract the canonical ATT&CK external ID from STIX references."""

    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def _reference_url(item: dict[str, Any], fallback: str) -> str:
    """Extract the canonical MITRE page URL when present."""

    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("url"):
            return str(reference["url"])
    return fallback


def normalize_mitre_bundle(artifact: RawArtifact, entry: SourceEntry) -> list[KnowledgeDocument]:
    """Normalize allowlisted Enterprise ATT&CK techniques and sub-techniques."""

    bundle = json.loads(artifact.path.read_text(encoding="utf-8"))
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("MITRE STIX bundle is missing an objects list")
    allowlist = set(entry.technique_allowlist)
    documents: list[KnowledgeDocument] = []
    for item in objects:
        if not isinstance(item, dict) or item.get("type") != "attack-pattern":
            continue
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        technique_id = _external_id(item)
        if not technique_id or (allowlist and technique_id not in allowlist):
            continue
        name = str(item.get("name") or technique_id)
        tactics = sorted(
            {
                str(phase["phase_name"])
                for phase in item.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            }
        )
        description = str(item.get("description") or "")
        detection = str(item.get("x_mitre_detection") or "")
        content = normalize_text(
            "\n".join(
                [
                    f"Technique: {technique_id} {name}",
                    f"Tactics: {', '.join(tactics)}",
                    "Description:",
                    description,
                    "Detection guidance:",
                    detection,
                ]
            )
        )
        is_subtechnique = bool(item.get("x_mitre_is_subtechnique"))
        parent_id = technique_id.rsplit(".", 1)[0] if is_subtechnique else None
        version = str(item.get("x_mitre_version") or entry.version)
        documents.append(
            KnowledgeDocument(
                document_id=f"mitre-{technique_id.lower().replace('.', '-')}",
                source="mitre_attack",
                source_type=entry.source_type,
                title=f"{technique_id} {name}",
                url=_reference_url(item, artifact.url),
                content=content,
                content_hash=sha256_text(content),
                version=version,
                effective_or_modified_date=str(item.get("modified") or "") or None,
                downloaded_at=artifact.downloaded_at,
                raw_path=artifact.path.as_posix(),
                technique_id=parent_id or technique_id,
                subtechnique_id=technique_id if is_subtechnique else None,
                metadata={
                    "name": name,
                    "tactics": tactics,
                    "is_subtechnique": is_subtechnique,
                    "parent_technique_id": parent_id,
                    "stix_id": item.get("id"),
                    "raw_content_hash": artifact.content_hash,
                },
            )
        )
    if not documents:
        raise ValueError("MITRE STIX bundle produced no allowlisted techniques")
    return sorted(documents, key=lambda document: document.document_id)

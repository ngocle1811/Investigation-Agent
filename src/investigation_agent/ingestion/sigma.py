"""Sigma YAML rule normalization with one rule per logical document."""

from typing import Any

import yaml

from investigation_agent.ingestion.schemas import KnowledgeDocument, RawArtifact, SourceEntry
from investigation_agent.ingestion.utils import normalize_text, sha256_text


def _as_text(value: Any) -> str | None:
    """Convert YAML scalar dates and identifiers into JSON-safe text."""

    return str(value) if value is not None else None


def normalize_sigma_rule(artifact: RawArtifact, entry: SourceEntry) -> KnowledgeDocument:
    """Normalize one Sigma YAML file without splitting its detection logic."""

    raw_rule = normalize_text(artifact.path.read_text(encoding="utf-8"))
    parsed = yaml.safe_load(raw_rule)
    if not isinstance(parsed, dict):
        raise ValueError(f"Sigma rule {entry.id} must contain a YAML mapping")
    title = _as_text(parsed.get("title"))
    rule_id = _as_text(parsed.get("id"))
    detection = parsed.get("detection")
    if not title or not rule_id or not isinstance(detection, dict):
        raise ValueError(f"Sigma rule {entry.id} is missing title, id, or detection")

    logsource = parsed.get("logsource") if isinstance(parsed.get("logsource"), dict) else {}
    content = normalize_text(
        "\n".join(
            [
                f"Title: {title}",
                f"Description: {_as_text(parsed.get('description')) or ''}",
                "Log source:",
                yaml.safe_dump(logsource, sort_keys=True, allow_unicode=True).strip(),
                "Detection:",
                yaml.safe_dump(detection, sort_keys=True, allow_unicode=True).strip(),
                "False positives:",
                yaml.safe_dump(
                    parsed.get("falsepositives") or [], sort_keys=True, allow_unicode=True
                ).strip(),
                "Raw rule:",
                raw_rule,
            ]
        )
    )
    modified = _as_text(parsed.get("modified") or parsed.get("date"))
    return KnowledgeDocument(
        document_id=f"sigma-{rule_id}",
        source="sigma",
        source_type=entry.source_type,
        title=title,
        url=artifact.url,
        content=content,
        content_hash=sha256_text(content),
        version=modified or entry.version,
        effective_or_modified_date=modified,
        downloaded_at=artifact.downloaded_at,
        raw_path=artifact.path.as_posix(),
        sigma_rule_id=rule_id,
        metadata={
            "status": _as_text(parsed.get("status")),
            "level": _as_text(parsed.get("level")),
            "tags": [str(item) for item in parsed.get("tags") or []],
            "logsource": {str(key): value for key, value in logsource.items()},
            "raw_content_hash": artifact.content_hash,
        },
    )

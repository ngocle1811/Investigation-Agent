"""Deterministic context prepends for embedding without altering citation text."""

from investigation_agent.ingestion.schemas import KnowledgeDocument
from investigation_agent.ingestion.utils import normalize_text


def contextualize(
    document: KnowledgeDocument,
    *,
    section: str,
    content: str,
    technique_id: str | None = None,
    tactic: str | None = None,
    event_id: int | None = None,
) -> str:
    """Prepend deterministic source context used only for embedding and retrieval."""

    if document.source_type == "windows_event_doc":
        context = [
            "Source: Microsoft Windows Security documentation",
            f"Event ID: {document.event_id}" if document.event_id is not None else None,
            f"Document: {document.title}",
            f"Section: {section}",
        ]
    elif document.source_type == "sysmon_doc":
        context = [
            "Source: Microsoft Sysmon documentation",
            f"Event ID: {event_id}" if event_id is not None else None,
            f"Document: {document.title}",
            f"Section: {section}",
        ]
    elif document.source_type == "sigma_rule":
        context = [
            "Source: Sigma rule",
            f"Rule: {document.title}",
            f"Level: {document.metadata.get('level') or 'unknown'}",
            f"Section: {section}",
        ]
    elif document.source_type == "mitre_attack":
        technique_name = document.metadata.get("name", "")
        context = [
            "Source: MITRE ATT&CK",
            f"Technique: {technique_id or document.technique_id} {technique_name}",
            f"Tactic: {tactic or 'unknown'}",
            f"Section: {section}",
        ]
    else:
        raise ValueError(f"Unsupported knowledge source type: {document.source_type}")
    header = "\n".join(item for item in context if item)
    return normalize_text(f"{header}\n\n{content}")

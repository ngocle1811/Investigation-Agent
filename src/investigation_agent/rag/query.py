"""Deterministic extraction of explicit knowledge identifiers from queries."""

import re

from investigation_agent.rag.dense import KnowledgeFilter

_EVENT_ID = re.compile(r"\bevent(?:\s+id)?\s*[:#-]?\s*(\d{1,5})\b", re.IGNORECASE)
_MITRE_ID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_SIGMA_ID = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)


def infer_identifier_filters(query: str) -> KnowledgeFilter:
    """Infer filters only from explicit Event, MITRE, or Sigma identifiers."""

    values: dict[str, object] = {}
    event_match = _EVENT_ID.search(query)
    if event_match:
        values["event_id"] = int(event_match.group(1))
        query_lower = query.casefold()
        if "sysmon" in query_lower:
            values["source_type"] = "sysmon_doc"
        elif "windows" in query_lower or "security" in query_lower:
            values["source_type"] = "windows_event_doc"

    mitre_match = _MITRE_ID.search(query)
    if mitre_match:
        values["technique_id"] = mitre_match.group(1).upper()
        values["source_type"] = "mitre_attack"

    sigma_match = _SIGMA_ID.search(query)
    if sigma_match and "sigma" in query.casefold():
        values["sigma_rule_id"] = sigma_match.group(1).lower()
        values["source_type"] = "sigma_rule"
    return KnowledgeFilter.model_validate(values)


def merge_filters(
    inferred: KnowledgeFilter,
    explicit: KnowledgeFilter | None,
) -> KnowledgeFilter:
    """Merge identifier hints with caller filters, giving explicit values precedence."""

    values = inferred.model_dump(exclude_none=True)
    if explicit:
        values.update(explicit.model_dump(exclude_none=True))
    return KnowledgeFilter.model_validate(values)

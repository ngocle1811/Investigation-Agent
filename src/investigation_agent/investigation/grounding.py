"""Deterministic post-generation validation of all incident and knowledge references."""

import re

from investigation_agent.investigation.schemas import (
    GroundingValidation,
    InvestigationContext,
    InvestigationReport,
)

_EVENT_MENTION = re.compile(r"\bINC-[SB]\d{2}-V\d{2}-E\d{4}\b")
_CHUNK_MENTION = re.compile(r"\bchk-[0-9a-f]{32}\b", re.IGNORECASE)


class GroundingValidationError(ValueError):
    """Raised when structured output cites evidence outside its bounded context."""

    def __init__(self, validation: GroundingValidation) -> None:
        self.validation = validation
        super().__init__(
            "investigation report failed grounding validation: "
            f"events={validation.unknown_event_ids}, "
            f"knowledge={validation.unknown_knowledge_chunk_ids}, "
            f"mitre={validation.unsupported_mitre_techniques}"
        )


def cited_event_ids(report: InvestigationReport) -> set[str]:
    """Collect every event reference from every incident-specific report section."""

    values = set(report.summary_evidence_event_ids)
    values.update(item.event_id for item in report.timeline)
    for finding in report.findings:
        values.update(finding.evidence_event_ids)
    for reason in report.why_suspicious:
        values.update(reason.evidence_event_ids)
    for technique in report.mitre_techniques:
        values.update(technique.evidence_event_ids)
    return values


def cited_knowledge_chunk_ids(report: InvestigationReport) -> set[str]:
    """Collect external-knowledge references from interpretations and MITRE mappings."""

    values: set[str] = set()
    for finding in report.findings:
        values.update(finding.knowledge_chunk_ids)
    for reason in report.why_suspicious:
        values.update(reason.knowledge_chunk_ids)
    for technique in report.mitre_techniques:
        values.update(technique.knowledge_chunk_ids)
    return values


def _chunk_supports_technique(technique_id: str, chunk) -> bool:
    if chunk.technique_id == technique_id:
        return True
    tags = chunk.metadata.get("tags", [])
    return any(str(tag).casefold() == f"attack.{technique_id}".casefold() for tag in tags)


def validate_report_grounding(
    report: InvestigationReport,
    context: InvestigationContext,
) -> GroundingValidation:
    """Reject IDs outside the prompt and MITRE mappings without cited retrieved support."""

    events_by_id = {event.event_id: event for event in context.related_events}
    known_events = set(events_by_id)
    known_knowledge = {item.chunk_id for item in context.retrieved_knowledge}
    serialized_report = report.model_dump_json()
    event_refs = cited_event_ids(report) | set(_EVENT_MENTION.findall(serialized_report))
    knowledge_refs = cited_knowledge_chunk_ids(report) | set(
        _CHUNK_MENTION.findall(serialized_report)
    )
    unknown_events = sorted(event_refs - known_events)
    unknown_knowledge = sorted(knowledge_refs - known_knowledge)
    timeline_valid = all(item.event_id in known_events for item in report.timeline)
    timestamps_valid = all(
        item.event_id in events_by_id and item.timestamp == events_by_id[item.event_id].timestamp
        for item in report.timeline
    )
    knowledge_by_id = {item.chunk_id: item for item in context.retrieved_knowledge}
    unsupported_mitre = sorted(
        {
            technique.technique_id
            for technique in report.mitre_techniques
            if not any(
                chunk_id in knowledge_by_id
                and _chunk_supports_technique(
                    technique.technique_id,
                    knowledge_by_id[chunk_id],
                )
                for chunk_id in technique.knowledge_chunk_ids
            )
        }
    )
    validation = GroundingValidation(
        valid=False,
        case_id_matches=report.case_id == context.case_id,
        all_evidence_refs_exist=not unknown_events,
        all_knowledge_refs_exist=not unknown_knowledge,
        timeline_event_ids_belong_to_case=timeline_valid,
        timeline_timestamps_match_evidence=timestamps_valid,
        mitre_knowledge_support_valid=not unsupported_mitre,
        unknown_event_ids=unknown_events,
        unknown_knowledge_chunk_ids=unknown_knowledge,
        unsupported_mitre_techniques=unsupported_mitre,
    )
    validation.valid = all(
        [
            validation.case_id_matches,
            validation.all_evidence_refs_exist,
            validation.all_knowledge_refs_exist,
            validation.timeline_event_ids_belong_to_case,
            validation.timeline_timestamps_match_evidence,
            validation.mitre_knowledge_support_valid,
        ]
    )
    return validation


def require_grounded_report(
    report: InvestigationReport,
    context: InvestigationContext,
) -> GroundingValidation:
    """Return validation evidence or fail closed on any fabricated reference."""

    validation = validate_report_grounding(report, context)
    if not validation.valid:
        raise GroundingValidationError(validation)
    return validation

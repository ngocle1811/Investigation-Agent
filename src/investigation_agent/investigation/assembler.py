"""Assemble bounded incident evidence for one existing candidate behavior."""

from investigation_agent.detection.schemas import (
    CandidateBehavior,
    DetectionConfig,
    InvestigationCase,
)
from investigation_agent.events.schemas import SecurityEvent
from investigation_agent.investigation.query import build_retrieval_query
from investigation_agent.investigation.schemas import (
    DetectionRuleContext,
    EvidenceEvent,
    InvestigationEvidence,
)

_USEFUL_RAW_FIELDS = {
    "action",
    "image",
    "logon_type",
    "matched_markers",
    "parent_image",
    "protocol",
    "query",
    "response",
    "status",
    "task_name",
}


def _evidence_event(event: SecurityEvent) -> EvidenceEvent:
    """Project a normalized event to useful evidence fields, excluding labels and raw dumps."""

    return EvidenceEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_type=event.source_type.value,
        source_event_id=event.source_event_id,
        event_type=event.event_type.value,
        host=event.host,
        user=event.user,
        process_name=event.process_name,
        parent_process_name=event.parent_process_name,
        process_id=event.process_id,
        parent_process_id=event.parent_process_id,
        command_line=event.command_line,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        dst_domain=event.dst_domain,
        file_path=event.file_path,
        details={key: event.raw[key] for key in sorted(_USEFUL_RAW_FIELDS & event.raw.keys())},
    )


class InvestigationCaseAssembler:
    """Resolve only evidence already linked by deterministic detection and correlation."""

    def __init__(self, detection_config: DetectionConfig) -> None:
        self.detection_config = detection_config

    def select_behavior(
        self,
        case: InvestigationCase,
        behavior_id: str | None = None,
    ) -> CandidateBehavior:
        """Select an explicit behavior or the strongest existing behavior deterministically."""

        if not case.candidate_behaviors:
            raise ValueError(f"case {case.case_id} has no candidate behavior to investigate")
        if behavior_id:
            for behavior in case.candidate_behaviors:
                if behavior.behavior_id == behavior_id:
                    return behavior
            raise ValueError(f"candidate behavior {behavior_id} not found in case {case.case_id}")
        return sorted(
            case.candidate_behaviors,
            key=lambda behavior: (
                -behavior.deterministic_score,
                behavior.start_time,
                behavior.behavior_id,
            ),
        )[0]

    def assemble(
        self,
        case: InvestigationCase,
        *,
        behavior_id: str | None = None,
    ) -> InvestigationEvidence:
        """Build an investigation input without inventing or expanding related evidence."""

        behavior = self.select_behavior(case, behavior_id)
        matches_by_id = {match.match_id: match for match in case.rule_matches}
        events_by_id = {event.event_id: event for event in case.events}
        matches = [matches_by_id[match_id] for match_id in behavior.supporting_rule_match_ids]
        events = [events_by_id[event_id] for event_id in behavior.supporting_event_ids]
        events.sort(key=lambda event: (event.timestamp, event.event_id))
        rule_ids = list(dict.fromkeys(match.rule_id for match in matches))
        rule_context = [
            DetectionRuleContext(
                rule_id=rule_id,
                name=self.detection_config.rules[rule_id].name,
                description=self.detection_config.rules[rule_id].description,
                mitre_techniques=self.detection_config.rules[rule_id].mitre_techniques,
            )
            for rule_id in rule_ids
        ]
        return InvestigationEvidence(
            case_id=case.case_id,
            candidate_behavior=behavior,
            rule_matches=matches,
            rule_context=rule_context,
            related_events=[_evidence_event(event) for event in events],
            retrieval_query=build_retrieval_query(
                behavior,
                matches,
                events,
                self.detection_config.rules,
            ),
            supplemental_retrieval_queries=[
                f"MITRE ATT&CK technique {technique_id}"
                for technique_id in dict.fromkeys(
                    technique for rule in rule_context for technique in rule.mitre_techniques
                )
            ],
        )

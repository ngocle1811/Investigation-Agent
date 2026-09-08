"""Build bounded investigation cases from normalized event collections."""

from collections.abc import Iterable

from investigation_agent.detection.behaviors import (
    aggregate_behaviors,
    severity_label_for_score,
)
from investigation_agent.detection.rules import DetectionEngine, entities_from_events
from investigation_agent.detection.schemas import (
    DetectionConfig,
    EvaluationGroundTruth,
    InvestigationCase,
)
from investigation_agent.events.schemas import SecurityEvent


def build_investigation_case(
    *,
    case_id: str,
    source_scenario_id: str,
    events: Iterable[SecurityEvent],
    engine: DetectionEngine,
    config: DetectionConfig,
    ground_truth: EvaluationGroundTruth | None = None,
) -> InvestigationCase:
    """Run rules and build one case without requiring evaluation ground truth."""

    canonical_events, rule_matches = engine.evaluate(case_id, events)
    if not canonical_events:
        raise ValueError("cannot build an investigation case without observed events")
    behaviors = aggregate_behaviors(case_id, rule_matches, canonical_events, config)
    matched_rule_ids = {match.rule_id for match in rule_matches}
    score = sum(
        config.severity_weights[config.rules[rule_id].severity] for rule_id in matched_rule_ids
    )
    entities = entities_from_events(canonical_events)
    return InvestigationCase(
        case_id=case_id,
        source_scenario_id=source_scenario_id,
        start_time=canonical_events[0].timestamp,
        end_time=canonical_events[-1].timestamp,
        hosts=entities.hosts,
        users=entities.users,
        ips=entities.ips,
        processes=entities.processes,
        events=canonical_events,
        rule_matches=rule_matches,
        candidate_behaviors=behaviors,
        severity_score=score,
        severity_label=severity_label_for_score(config, score),
        escalated=score >= config.case_scoring.escalation_threshold,
        status="new",
        ground_truth=ground_truth,
    )

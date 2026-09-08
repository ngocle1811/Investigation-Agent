"""Synthetic incident detection pipeline, evaluation, and stable export."""

import json
from pathlib import Path

from investigation_agent.detection.case_builder import build_investigation_case
from investigation_agent.detection.rules import DetectionEngine
from investigation_agent.detection.schemas import (
    CaseDetectionComparison,
    DetectionConfig,
    DetectionSummary,
    EvaluationGroundTruth,
    InvestigationCase,
)
from investigation_agent.events.schemas import IncidentCase
from investigation_agent.ingestion.utils import atomic_write_bytes


def observed_events(incident: IncidentCase):
    """Resolve a synthetic input view, preserving arbitrary ingest order and omissions."""

    events_by_id = {event.event_id: event for event in incident.events}
    return [events_by_id[event_id] for event_id in incident.metadata.input_event_ids]


def _evaluation_truth(incident: IncidentCase) -> EvaluationGroundTruth:
    return EvaluationGroundTruth(
        suspicious=incident.ground_truth.suspicious,
        expected_rule_ids=incident.ground_truth.expected_rule_ids,
        expected_behaviors=incident.ground_truth.expected_behaviors,
    )


def evaluate_detection(
    incidents: list[IncidentCase], cases: list[InvestigationCase]
) -> DetectionSummary:
    """Compare deterministic matches with static synthetic rule expectations."""

    incidents_by_id = {incident.case_id: incident for incident in incidents}
    comparisons: list[CaseDetectionComparison] = []
    for case in cases:
        incident = incidents_by_id[case.case_id]
        expected = sorted(set(incident.ground_truth.expected_rule_ids))
        actual = sorted({match.rule_id for match in case.rule_matches})
        hits = sorted(set(expected) & set(actual))
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        comparisons.append(
            CaseDetectionComparison(
                case_id=case.case_id,
                scenario_id=case.source_scenario_id,
                suspicious=incident.ground_truth.suspicious,
                expected_rules=expected,
                actual_rules=actual,
                expected_rule_hits=hits,
                missing_rules=missing,
                unexpected_rules=unexpected,
                detected=bool(hits) if incident.ground_truth.suspicious else bool(actual),
                escalated=case.escalated,
            )
        )

    expected_total = sum(len(item.expected_rules) for item in comparisons)
    expected_hits = sum(len(item.expected_rule_hits) for item in comparisons)
    suspicious = [item for item in comparisons if item.suspicious]
    benign = [item for item in comparisons if not item.suspicious]
    failures = [item for item in comparisons if item.missing_rules or item.unexpected_rules]
    return DetectionSummary(
        processed_cases=len(cases),
        total_rule_matches=sum(len(case.rule_matches) for case in cases),
        candidate_behaviors=sum(len(case.candidate_behaviors) for case in cases),
        suspicious_cases=len(suspicious),
        benign_cases=len(benign),
        suspicious_cases_detected=sum(item.detected for item in suspicious),
        suspicious_cases_missed=sum(not item.detected for item in suspicious),
        benign_cases_escalated=sum(item.escalated for item in benign),
        expected_rule_hits=expected_hits,
        expected_rule_total=expected_total,
        expected_rule_coverage=(
            round(expected_hits / expected_total, 4) if expected_total else 1.0
        ),
        unexpected_rule_hits=sum(len(item.unexpected_rules) for item in comparisons),
        comparisons=comparisons,
        failures=failures,
    )


def process_incidents(
    incidents: list[IncidentCase],
    config: DetectionConfig,
    *,
    include_ground_truth: bool = False,
) -> tuple[list[InvestigationCase], DetectionSummary]:
    """Convert one synthetic incident record into one deterministic investigation case."""

    engine = DetectionEngine(config)
    cases = [
        build_investigation_case(
            case_id=incident.case_id,
            source_scenario_id=incident.scenario_id,
            events=observed_events(incident),
            engine=engine,
            config=config,
            ground_truth=_evaluation_truth(incident) if include_ground_truth else None,
        )
        for incident in incidents
    ]
    return cases, evaluate_detection(incidents, cases)


def write_detection_outputs(
    cases: list[InvestigationCase],
    summary: DetectionSummary,
    *,
    output_path: Path,
    summary_path: Path,
) -> tuple[bool, bool]:
    """Write stable JSONL cases and human-readable evaluation summary atomically."""

    case_bytes = (
        "\n".join(case.model_dump_json(exclude_none=False) for case in cases) + "\n"
    ).encode("utf-8")
    summary_bytes = (
        json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    cases_changed = not output_path.exists() or output_path.read_bytes() != case_bytes
    summary_changed = not summary_path.exists() or summary_path.read_bytes() != summary_bytes
    if cases_changed:
        atomic_write_bytes(output_path, case_bytes)
    if summary_changed:
        atomic_write_bytes(summary_path, summary_bytes)
    return cases_changed, summary_changed


def load_investigation_cases(path: Path) -> list[InvestigationCase]:
    """Load and validate exported investigation case JSONL."""

    cases: list[InvestigationCase] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            cases.append(InvestigationCase.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid investigation case JSONL at line {line_number}") from exc
    return cases

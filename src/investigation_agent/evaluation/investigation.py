"""Deterministic validation and evaluation for representative investigation runs."""

import json
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from investigation_agent.detection.schemas import DetectionConfig, InvestigationCase
from investigation_agent.investigation.grounding import cited_event_ids
from investigation_agent.investigation.schemas import InvestigationRun


class InvestigationDemoCase(BaseModel):
    """Manually curated expectations for one existing detected behavior."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    behavior_id: str
    expected_behavior_type: str
    expected_key_event_ids: list[str] = Field(min_length=1)
    expected_rule_ids: list[str] = Field(min_length=1)
    expected_mitre_techniques: list[str]
    expected_theme: str = Field(min_length=10)


class InvestigationEvaluation(BaseModel):
    """Stable checks that do not assert exact model prose."""

    case_id: str
    report_schema_valid: bool
    all_evidence_refs_exist: bool
    all_knowledge_refs_exist: bool
    expected_key_events_cited: bool
    no_hallucinated_event_ids: bool
    timeline_event_ids_belong_to_case: bool
    timeline_timestamps_match_evidence: bool
    recommended_action_present: bool
    expected_mitre_coverage: bool
    missing_key_event_ids: list[str]
    missing_mitre_techniques: list[str]
    passed: bool

    @model_validator(mode="after")
    def passed_must_match_checks(self) -> Self:
        checks = [
            self.report_schema_valid,
            self.all_evidence_refs_exist,
            self.all_knowledge_refs_exist,
            self.expected_key_events_cited,
            self.no_hallucinated_event_ids,
            self.timeline_event_ids_belong_to_case,
            self.timeline_timestamps_match_evidence,
            self.recommended_action_present,
            self.expected_mitre_coverage,
        ]
        if self.passed != all(checks):
            raise ValueError("investigation evaluation passed flag disagrees with checks")
        return self


class InvestigationEvaluationSummary(BaseModel):
    total_cases: int
    passed_cases: int
    failed_cases: int
    evaluations: list[InvestigationEvaluation]


def load_investigation_demo_cases(path: Path) -> list[InvestigationDemoCase]:
    """Load the small, checked-in demo set as strict structured data."""

    return [
        InvestigationDemoCase.model_validate(item)
        for item in json.loads(path.read_text(encoding="utf-8"))
    ]


def validate_investigation_demo_cases(
    demos: list[InvestigationDemoCase],
    cases: list[InvestigationCase],
    detection_config: DetectionConfig,
) -> None:
    """Prove fixtures point to real behaviors, event IDs, rules, and configured mappings."""

    if len({demo.case_id for demo in demos}) != len(demos):
        raise ValueError("investigation demo case IDs must be unique")
    cases_by_id = {case.case_id: case for case in cases}
    for demo in demos:
        case = cases_by_id.get(demo.case_id)
        if case is None:
            raise ValueError(f"demo references missing case: {demo.case_id}")
        behavior = next(
            (item for item in case.candidate_behaviors if item.behavior_id == demo.behavior_id),
            None,
        )
        if behavior is None:
            raise ValueError(f"demo references missing behavior: {demo.behavior_id}")
        if behavior.behavior_type != demo.expected_behavior_type:
            raise ValueError(f"demo behavior type disagrees for {demo.case_id}")
        if not set(demo.expected_key_event_ids).issubset(behavior.supporting_event_ids):
            raise ValueError(f"demo key events are outside the behavior for {demo.case_id}")
        matches_by_id = {match.match_id: match for match in case.rule_matches}
        actual_rules = {
            matches_by_id[match_id].rule_id for match_id in behavior.supporting_rule_match_ids
        }
        if set(demo.expected_rule_ids) != actual_rules:
            raise ValueError(f"demo rule expectations disagree for {demo.case_id}")
        configured_mitre = {
            technique
            for rule_id in actual_rules
            for technique in detection_config.rules[rule_id].mitre_techniques
        }
        if not set(demo.expected_mitre_techniques).issubset(configured_mitre):
            raise ValueError(f"demo MITRE expectations disagree for {demo.case_id}")


def evaluate_investigation_run(
    run: InvestigationRun,
    demo: InvestigationDemoCase,
) -> InvestigationEvaluation:
    """Evaluate references, key evidence, MITRE coverage, and basic usefulness."""

    cited_events = cited_event_ids(run.report)
    missing_events = sorted(set(demo.expected_key_event_ids) - cited_events)
    actual_techniques = {item.technique_id for item in run.report.mitre_techniques}
    missing_techniques = sorted(set(demo.expected_mitre_techniques) - actual_techniques)
    checks = {
        "report_schema_valid": True,
        "all_evidence_refs_exist": run.grounding.all_evidence_refs_exist,
        "all_knowledge_refs_exist": run.grounding.all_knowledge_refs_exist,
        "expected_key_events_cited": not missing_events,
        "no_hallucinated_event_ids": not run.grounding.unknown_event_ids,
        "timeline_event_ids_belong_to_case": run.grounding.timeline_event_ids_belong_to_case,
        "timeline_timestamps_match_evidence": run.grounding.timeline_timestamps_match_evidence,
        "recommended_action_present": bool(run.report.recommended_actions),
        "expected_mitre_coverage": not missing_techniques,
    }
    return InvestigationEvaluation(
        case_id=demo.case_id,
        **checks,
        missing_key_event_ids=missing_events,
        missing_mitre_techniques=missing_techniques,
        passed=all(checks.values()),
    )


def summarize_investigation_evaluations(
    evaluations: list[InvestigationEvaluation],
) -> InvestigationEvaluationSummary:
    """Aggregate the three transparent demo checks without an LLM judge."""

    passed = sum(item.passed for item in evaluations)
    return InvestigationEvaluationSummary(
        total_cases=len(evaluations),
        passed_cases=passed,
        failed_cases=len(evaluations) - passed,
        evaluations=evaluations,
    )

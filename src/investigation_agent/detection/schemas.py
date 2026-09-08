"""Strict schemas for deterministic rules, matches, behaviors, and cases."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from investigation_agent.events.schemas import SecurityEvent


class Severity(StrEnum):
    """Ordered severity names whose numeric weights live in configuration."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleType(StrEnum):
    """Supported deterministic rule execution shapes."""

    EVENT = "event"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    PARENT_CHILD = "parent_child"


class DetectionRule(BaseModel):
    """One configuration-owned rule definition and its parameters."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=r"^R\d{3}$")
    name: str = Field(min_length=3)
    description: str = Field(min_length=10)
    severity: Severity
    enabled: bool = True
    rule_type: RuleType
    parameters: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)

    @field_validator("mitre_techniques")
    @classmethod
    def mitre_ids_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("MITRE technique IDs must be unique")
        return values


class CaseScoringConfig(BaseModel):
    """Configurable deterministic thresholds for case classification."""

    model_config = ConfigDict(extra="forbid")

    escalation_threshold: int = Field(ge=1)
    label_thresholds: dict[Severity, int]

    @model_validator(mode="after")
    def thresholds_must_be_complete_and_ordered(self) -> Self:
        if set(self.label_thresholds) != set(Severity):
            raise ValueError("label_thresholds must configure every severity")
        ordered = [self.label_thresholds[level] for level in Severity]
        if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
            raise ValueError("severity label thresholds must increase strictly")
        return self


class DetectionConfig(BaseModel):
    """Validated root of ``config/correlation_rules.yaml``."""

    model_config = ConfigDict(extra="forbid")

    severity_weights: dict[Severity, int]
    case_scoring: CaseScoringConfig
    rules: dict[str, DetectionRule]

    @model_validator(mode="after")
    def validate_rule_keys_and_weights(self) -> Self:
        if set(self.severity_weights) != set(Severity):
            raise ValueError("severity_weights must configure every severity")
        if any(weight <= 0 for weight in self.severity_weights.values()):
            raise ValueError("severity weights must be positive")
        mismatched = [key for key, rule in self.rules.items() if key != rule.rule_id]
        if mismatched:
            raise ValueError(f"rule mapping keys do not match rule_id: {mismatched}")
        return self


class EntitySet(BaseModel):
    """Normalized entities attached to matches, behaviors, and cases."""

    model_config = ConfigDict(extra="forbid")

    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)

    @field_validator("hosts", "users", "ips", "processes", "domains")
    @classmethod
    def entity_values_are_stable(cls, values: list[str]) -> list[str]:
        return sorted(set(values), key=str.casefold)


class RuleMatch(BaseModel):
    """Traceable deterministic rule result referencing original event IDs."""

    model_config = ConfigDict(extra="forbid")

    match_id: str = Field(pattern=r"^RM-INC-[SB]\d{2}-V\d{2}-R\d{3}-[0-9a-f]{12}$")
    rule_id: str = Field(pattern=r"^R\d{3}$")
    case_id: str = Field(pattern=r"^INC-[SB]\d{2}-V\d{2}$")
    matched_event_ids: list[str] = Field(min_length=1)
    start_time: datetime
    end_time: datetime
    entities: EntitySet
    severity: Severity
    reason: str = Field(min_length=10)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_range_and_references(self) -> Self:
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("rule match timestamps must be timezone-aware")
        if self.start_time > self.end_time:
            raise ValueError("rule match start_time must not exceed end_time")
        if len(self.matched_event_ids) != len(set(self.matched_event_ids)):
            raise ValueError("matched event IDs must be unique")
        return self


class CandidateBehavior(BaseModel):
    """Aggregated behavior supported by rule matches and deduplicated evidence."""

    model_config = ConfigDict(extra="forbid")

    behavior_id: str = Field(pattern=r"^BH-INC-[SB]\d{2}-V\d{2}-[a-z0-9_]+-[0-9a-f]{12}$")
    behavior_type: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    case_id: str = Field(pattern=r"^INC-[SB]\d{2}-V\d{2}$")
    supporting_rule_match_ids: list[str] = Field(min_length=1)
    supporting_event_ids: list[str] = Field(min_length=1)
    start_time: datetime
    end_time: datetime
    entities: EntitySet
    severity: Severity
    deterministic_score: int = Field(ge=1)
    description: str = Field(min_length=10)

    @model_validator(mode="after")
    def validate_behavior(self) -> Self:
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("behavior timestamps must be timezone-aware")
        if self.start_time > self.end_time:
            raise ValueError("behavior start_time must not exceed end_time")
        if len(self.supporting_rule_match_ids) != len(set(self.supporting_rule_match_ids)):
            raise ValueError("supporting rule match IDs must be unique")
        if len(self.supporting_event_ids) != len(set(self.supporting_event_ids)):
            raise ValueError("supporting event IDs must be unique")
        return self


class EvaluationGroundTruth(BaseModel):
    """Optional evaluation-only truth; runtime case building does not consume it."""

    model_config = ConfigDict(extra="forbid")

    suspicious: bool
    expected_rule_ids: list[str]
    expected_behaviors: list[str]


class InvestigationCase(BaseModel):
    """Bounded evidence case produced before any RAG or model invocation."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^INC-[SB]\d{2}-V\d{2}$")
    source_scenario_id: str = Field(pattern=r"^[SB]\d{2}$")
    start_time: datetime
    end_time: datetime
    hosts: list[str]
    users: list[str]
    ips: list[str]
    processes: list[str]
    events: list[SecurityEvent] = Field(min_length=1)
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    candidate_behaviors: list[CandidateBehavior] = Field(default_factory=list)
    severity_score: int = Field(ge=0)
    severity_label: Literal["none", "informational", "low", "medium", "high"]
    escalated: bool
    status: Literal["new", "closed"] = "new"
    ground_truth: EvaluationGroundTruth | None = None

    @model_validator(mode="after")
    def validate_case_references(self) -> Self:
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("case timestamps must be timezone-aware")
        if self.start_time > self.end_time:
            raise ValueError("case start_time must not exceed end_time")
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("case events must be deduplicated")
        if [event.timestamp for event in self.events] != sorted(
            event.timestamp for event in self.events
        ):
            raise ValueError("case events must be in canonical time order")
        known_events = set(event_ids)
        match_ids = {match.match_id for match in self.rule_matches}
        if len(match_ids) != len(self.rule_matches):
            raise ValueError("rule match IDs must be unique")
        if any(
            not set(match.matched_event_ids).issubset(known_events) for match in self.rule_matches
        ):
            raise ValueError("rule matches reference events outside the case")
        behavior_ids = [behavior.behavior_id for behavior in self.candidate_behaviors]
        if len(behavior_ids) != len(set(behavior_ids)):
            raise ValueError("candidate behavior IDs must be unique")
        if any(
            not set(behavior.supporting_event_ids).issubset(known_events)
            or not set(behavior.supporting_rule_match_ids).issubset(match_ids)
            for behavior in self.candidate_behaviors
        ):
            raise ValueError("candidate behaviors reference unknown evidence")
        return self


class CaseDetectionComparison(BaseModel):
    """Expected-versus-actual rules for one synthetic case."""

    case_id: str
    scenario_id: str
    suspicious: bool
    expected_rules: list[str]
    actual_rules: list[str]
    expected_rule_hits: list[str]
    missing_rules: list[str]
    unexpected_rules: list[str]
    detected: bool
    escalated: bool


class DetectionSummary(BaseModel):
    """Deterministic Checkpoint 4 run and ground-truth comparison summary."""

    processed_cases: int
    total_rule_matches: int
    candidate_behaviors: int
    suspicious_cases: int
    benign_cases: int
    suspicious_cases_detected: int
    suspicious_cases_missed: int
    benign_cases_escalated: int
    expected_rule_hits: int
    expected_rule_total: int
    expected_rule_coverage: float
    unexpected_rule_hits: int
    comparisons: list[CaseDetectionComparison]
    failures: list[CaseDetectionComparison]

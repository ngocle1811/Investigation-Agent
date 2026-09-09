"""Strict inputs, outputs, and validation records for grounded investigations."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from investigation_agent.detection.schemas import CandidateBehavior, RuleMatch


class StrictModel(BaseModel):
    """Forbid undeclared model output fields throughout the investigation contract."""

    model_config = ConfigDict(extra="forbid")


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ClaimType(StrEnum):
    FACT = "fact"
    INFERENCE = "inference"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceEvent(StrictModel):
    """A deliberately bounded event view passed to the investigator."""

    event_id: str
    timestamp: datetime
    source_type: str
    source_event_id: str | None
    event_type: str
    host: str | None
    user: str | None
    process_name: str | None
    parent_process_name: str | None
    process_id: str | None
    parent_process_id: str | None
    command_line: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    dst_domain: str | None
    file_path: str | None
    details: dict[str, Any]


class DetectionRuleContext(StrictModel):
    """Trusted configuration context for a rule that supports the selected behavior."""

    rule_id: str = Field(pattern=r"^R\d{3}$")
    name: str
    description: str
    mitre_techniques: list[str]


class InvestigationKnowledge(StrictModel):
    """Exactly the retrieved provenance and text supplied to the investigator."""

    citation_id: str = Field(pattern=r"^K[1-9]\d*$")
    rank: int = Field(ge=1)
    score: float
    chunk_id: str
    document_id: str
    source: str
    source_type: str
    title: str
    section: str
    url: str
    technique_id: str | None
    sigma_rule_id: str | None
    content: str
    metadata: dict[str, Any]


class InvestigationEvidence(StrictModel):
    """Detection-owned evidence assembled before knowledge retrieval or LLM invocation."""

    case_id: str
    candidate_behavior: CandidateBehavior
    rule_matches: list[RuleMatch] = Field(min_length=1)
    rule_context: list[DetectionRuleContext] = Field(min_length=1)
    related_events: list[EvidenceEvent] = Field(min_length=1)
    retrieval_query: str = Field(min_length=10)
    supplemental_retrieval_queries: list[str]

    @model_validator(mode="after")
    def references_must_match_selected_behavior(self) -> Self:
        if self.candidate_behavior.case_id != self.case_id:
            raise ValueError("candidate behavior belongs to a different case")
        match_ids = {match.match_id for match in self.rule_matches}
        if match_ids != set(self.candidate_behavior.supporting_rule_match_ids):
            raise ValueError("assembled rule matches do not match candidate behavior references")
        event_ids = {event.event_id for event in self.related_events}
        if event_ids != set(self.candidate_behavior.supporting_event_ids):
            raise ValueError("assembled events do not match candidate behavior references")
        if {rule.rule_id for rule in self.rule_context} != {
            match.rule_id for match in self.rule_matches
        }:
            raise ValueError("rule context does not cover assembled rule matches")
        return self


class InvestigationContext(InvestigationEvidence):
    """Complete bounded prompt context including dense-retrieved knowledge."""

    retrieved_knowledge: list[InvestigationKnowledge] = Field(min_length=1)


class TimelineItem(StrictModel):
    event_id: str
    timestamp: datetime
    description: str = Field(min_length=5)


class Finding(StrictModel):
    title: str = Field(min_length=3)
    explanation: str = Field(min_length=10)
    claim_type: ClaimType
    evidence_event_ids: list[str] = Field(min_length=1)
    knowledge_chunk_ids: list[str]
    confidence: Confidence

    @field_validator("evidence_event_ids")
    @classmethod
    def evidence_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("finding evidence IDs must be unique")
        return values


class SuspiciousReason(StrictModel):
    reason: str = Field(min_length=10)
    evidence_event_ids: list[str] = Field(min_length=1)
    knowledge_chunk_ids: list[str]


class MitreTechnique(StrictModel):
    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(min_length=2)
    reason: str = Field(min_length=10)
    evidence_event_ids: list[str] = Field(min_length=1)
    knowledge_chunk_ids: list[str] = Field(min_length=1)


class RecommendedAction(StrictModel):
    action: str = Field(min_length=5)
    reason: str = Field(min_length=10)
    priority: Priority


class InvestigationReport(StrictModel):
    """Provider-independent structured report with mandatory evidence references."""

    case_id: str
    summary: str = Field(min_length=10)
    summary_evidence_event_ids: list[str] = Field(min_length=1)
    timeline: list[TimelineItem] = Field(min_length=1)
    findings: list[Finding] = Field(min_length=1)
    why_suspicious: list[SuspiciousReason] = Field(min_length=1)
    mitre_techniques: list[MitreTechnique]
    recommended_actions: list[RecommendedAction] = Field(min_length=1)
    limitations: list[str] = Field(min_length=1)


class GroundingValidation(StrictModel):
    """Deterministic post-generation evidence and knowledge validation outcome."""

    valid: bool
    case_id_matches: bool
    all_evidence_refs_exist: bool
    all_knowledge_refs_exist: bool
    timeline_event_ids_belong_to_case: bool
    timeline_timestamps_match_evidence: bool
    mitre_knowledge_support_valid: bool
    unknown_event_ids: list[str]
    unknown_knowledge_chunk_ids: list[str]
    unsupported_mitre_techniques: list[str]


class LLMGeneration(StrictModel):
    """Structured provider result with lightweight usage and timing metadata."""

    report: InvestigationReport
    provider: str
    model: str
    latency_ms: float = Field(ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)


class InvestigationRun(StrictModel):
    """Inspectable end-to-end result returned by the investigation service and CLI."""

    context: InvestigationContext
    report: InvestigationReport
    grounding: GroundingValidation
    llm_provider: str
    llm_model: str
    llm_latency_ms: float
    prompt_tokens: int | None
    completion_tokens: int | None

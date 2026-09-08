"""Validated schemas for normalized security events and synthetic incidents."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SourceType(StrEnum):
    """Normalized telemetry families used by the MVP."""

    WINDOWS_SECURITY = "windows_security"
    SYSMON = "sysmon"
    NETWORK = "network"
    DNS = "dns"


class EventType(StrEnum):
    """Stable semantic event types consumed by later detection rules."""

    FAILED_LOGON = "failed_logon"
    SUCCESSFUL_LOGON = "successful_logon"
    PROCESS_CREATE = "process_create"
    PROCESS_ACCESS = "process_access"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_CREATE = "file_create"
    SCHEDULED_TASK_CREATE = "scheduled_task_create"
    SCHEDULED_TASK_EXECUTE = "scheduled_task_execute"


class SecurityEvent(BaseModel):
    """One normalized incident event with nullable source-specific fields."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(pattern=r"^INC-[SB]\d{2}-V\d{2}-E\d{4}$")
    timestamp: datetime
    source_type: SourceType
    source_event_id: str | None = None
    event_type: EventType
    host: str | None = None
    user: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    process_id: str | None = None
    parent_process_id: str | None = None
    command_line: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    dst_domain: str | None = None
    file_path: str | None = None
    file_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    raw: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str = Field(pattern=r"^[SB]\d{2}$")
    ground_truth_labels: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Reject ambiguous local timestamps in generated and imported evidence."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_event_specific_fields(self) -> Self:
        """Require the minimum fields needed to interpret each semantic event type."""

        if self.event_type in {EventType.FAILED_LOGON, EventType.SUCCESSFUL_LOGON}:
            if not all((self.host, self.user, self.src_ip)):
                raise ValueError("authentication events require host, user, and src_ip")
        if self.event_type in {
            EventType.PROCESS_CREATE,
            EventType.PROCESS_ACCESS,
            EventType.SCHEDULED_TASK_EXECUTE,
        } and not all((self.process_name, self.process_id)):
            raise ValueError(f"{self.event_type} requires process_name and process_id")
        if self.event_type == EventType.NETWORK_CONNECTION and not all(
            (self.dst_ip, self.dst_port)
        ):
            raise ValueError("network connections require dst_ip and dst_port")
        if self.event_type == EventType.DNS_QUERY and not self.dst_domain:
            raise ValueError("DNS queries require dst_domain")
        if self.event_type == EventType.FILE_CREATE and not self.file_path:
            raise ValueError("file creation requires file_path")
        return self


class TemplateEntities(BaseModel):
    """Semantic entity selectors resolved independently for every case variant."""

    model_config = ConfigDict(extra="forbid")

    host: str
    user: str
    src_ip: str
    domain: str | None = None
    process: str | None = None


class TemplateGroundTruth(BaseModel):
    """Human-authored expectations that never depend on runtime-generated IDs."""

    model_config = ConfigDict(extra="forbid")

    suspicious: bool
    expected_event_roles: list[str] = Field(min_length=1)
    expected_behaviors: list[str] = Field(min_length=1)
    expected_rule_ids: list[str] = Field(default_factory=list)
    expected_mitre: list[str] = Field(default_factory=list)
    expected_next_action_categories: list[str] = Field(min_length=1)

    @field_validator(
        "expected_event_roles",
        "expected_behaviors",
        "expected_rule_ids",
        "expected_mitre",
        "expected_next_action_categories",
    )
    @classmethod
    def values_must_be_unique(cls, values: list[str]) -> list[str]:
        """Keep evaluation expectations unambiguous."""

        if len(values) != len(set(values)):
            raise ValueError("ground-truth lists must not contain duplicates")
        return values


class ScenarioTemplate(BaseModel):
    """One data-driven scenario story and its immutable evaluation truth."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^[SB]\d{2}$")
    category: Literal["suspicious", "benign"]
    name: str = Field(min_length=3)
    description: str = Field(min_length=10)
    entities: TemplateEntities
    ground_truth: TemplateGroundTruth

    @model_validator(mode="after")
    def category_must_match_truth(self) -> Self:
        """Prevent an accidental benign/suspicious label inversion in configuration."""

        expected = self.category == "suspicious"
        if self.ground_truth.suspicious != expected:
            raise ValueError("template category must match ground_truth.suspicious")
        return self


class ScenarioCatalog(BaseModel):
    """Strict scenario template configuration root."""

    model_config = ConfigDict(extra="forbid")

    templates: list[ScenarioTemplate] = Field(min_length=1)

    @model_validator(mode="after")
    def template_ids_must_be_unique(self) -> Self:
        """Reject ambiguous scenario dispatch."""

        identifiers = [template.scenario_id for template in self.templates]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("scenario IDs must be unique")
        return self


class CaseEntities(BaseModel):
    """Concrete safe synthetic entities used in one generated case."""

    host: str
    user: str
    src_ip: str
    dst_ip: str
    domain: str
    process: str | None = None


class CaseMetadata(BaseModel):
    """Generation provenance plus canonical and simulated ingest ordering."""

    template_name: str
    template_description: str
    seed: int
    variant_seed: int
    entities: CaseEntities
    noise_event_count: int = Field(ge=20, le=80)
    relevant_event_count: int = Field(ge=3, le=10)
    canonical_timeline: bool = True
    input_event_ids: list[str] = Field(min_length=1)
    missing_event_ids: list[str] = Field(default_factory=list)
    edge_cases: list[str] = Field(default_factory=list)


class GeneratedGroundTruth(BaseModel):
    """Template truth resolved to deterministic event IDs for evaluation."""

    suspicious: bool
    relevant_event_ids: list[str] = Field(min_length=1)
    event_roles: dict[str, list[str]]
    expected_behaviors: list[str] = Field(min_length=1)
    expected_rule_ids: list[str] = Field(default_factory=list)
    expected_mitre: list[str] = Field(default_factory=list)
    expected_next_action_categories: list[str] = Field(min_length=1)


class IncidentCase(BaseModel):
    """A complete canonical incident timeline and deterministic ground truth."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^[SB]\d{2}$")
    variant_id: str = Field(pattern=r"^V\d{2}$")
    case_id: str = Field(pattern=r"^INC-[SB]\d{2}-V\d{2}$")
    metadata: CaseMetadata
    events: list[SecurityEvent] = Field(min_length=1)
    ground_truth: GeneratedGroundTruth

    @model_validator(mode="after")
    def validate_event_references_and_order(self) -> Self:
        """Guarantee unique IDs, canonical time order, and resolvable truth references."""

        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event IDs must be unique within a case")
        if [event.timestamp for event in self.events] != sorted(
            event.timestamp for event in self.events
        ):
            raise ValueError("events must use canonical timestamp order")
        if any(event.scenario_id != self.scenario_id for event in self.events):
            raise ValueError("every event must reference its containing scenario")
        known = set(event_ids)
        if not set(self.ground_truth.relevant_event_ids).issubset(known):
            raise ValueError("ground truth references unknown event IDs")
        role_ids = {
            event_id
            for identifiers in self.ground_truth.event_roles.values()
            for event_id in identifiers
        }
        if not role_ids.issubset(known):
            raise ValueError("event role mapping references unknown event IDs")
        input_ids = self.metadata.input_event_ids
        missing_ids = self.metadata.missing_event_ids
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("input event order must not repeat canonical event IDs")
        if len(missing_ids) != len(set(missing_ids)):
            raise ValueError("missing event IDs must be unique")
        if not set(input_ids).issubset(known) or not set(missing_ids).issubset(known):
            raise ValueError("input metadata references unknown event IDs")
        if set(input_ids) & set(missing_ids):
            raise ValueError("an event cannot be both observed and missing")
        if set(input_ids) | set(missing_ids) != known:
            raise ValueError("observed and missing event IDs must cover the canonical case")
        return self


class DatasetSummary(BaseModel):
    """Small deterministic dataset report written beside the generated JSONL."""

    seed: int
    variants: int = Field(ge=1)
    scenario_count: int
    case_count: int
    suspicious_case_count: int
    benign_case_count: int
    total_events: int
    average_events_per_case: float
    min_events_per_case: int
    max_events_per_case: int

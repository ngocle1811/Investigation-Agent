"""Validated models for source configuration and normalized knowledge."""

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceEntry(BaseModel):
    """One curated remote knowledge source."""

    model_config = ConfigDict(extra="forbid")

    id: str
    url: str
    raw_filename: str
    source_type: str
    version: str
    event_id: int | None = None
    enabled: bool = True
    technique_allowlist: list[str] = Field(default_factory=list)

    @field_validator("raw_filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        """Reject paths so a config entry cannot escape its source directory."""

        if Path(value).name != value or value in {".", ".."}:
            raise ValueError("raw_filename must be a plain filename")
        return value


class SourcesConfig(BaseModel):
    """Curated source list loaded from config/sources.yaml."""

    model_config = ConfigDict(extra="forbid")

    microsoft_pages: list[SourceEntry]
    sysmon_pages: list[SourceEntry]
    sigma_rules: list[SourceEntry]
    mitre_attack: SourceEntry


class RawArtifact(BaseModel):
    """A downloaded source plus immutable provenance metadata."""

    source: str
    source_type: str
    url: str
    path: Path
    downloaded_at: datetime
    content_hash: str
    version: str
    etag: str | None = None
    last_modified: str | None = None


class KnowledgeDocument(BaseModel):
    """Normalized logical document before source-specific chunking."""

    document_id: str
    source: str
    source_type: str
    title: str
    url: str
    content: str = Field(min_length=1)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str
    effective_or_modified_date: str | None = None
    downloaded_at: datetime
    raw_path: str
    event_id: int | None = None
    technique_id: str | None = None
    subtechnique_id: str | None = None
    sigma_rule_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestionSummary(BaseModel):
    """Deterministic preparation result suitable for CLI and logging."""

    output_path: str
    documents: int
    by_source: dict[str, int]
    added: int
    updated: int
    unchanged: int
    output_changed: bool

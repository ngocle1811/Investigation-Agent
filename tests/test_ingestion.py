"""Checkpoint 1 source loading, normalization, and idempotency tests."""

from datetime import UTC, datetime
from pathlib import Path

import httpx

from investigation_agent.ingestion.fetch import RawStore
from investigation_agent.ingestion.microsoft import normalize_microsoft_document
from investigation_agent.ingestion.mitre import normalize_mitre_bundle
from investigation_agent.ingestion.pipeline import prepare_knowledge
from investigation_agent.ingestion.schemas import RawArtifact, SourceEntry
from investigation_agent.ingestion.sigma import normalize_sigma_rule
from investigation_agent.ingestion.sysmon import normalize_sysmon_document
from investigation_agent.ingestion.utils import sha256_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "ingestion"
DOWNLOADED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def artifact_for(path: Path, source: str, source_type: str) -> RawArtifact:
    """Create stable provenance for a local parser fixture."""

    return RawArtifact(
        source=source,
        source_type=source_type,
        url=f"https://example.test/{path.name}",
        path=path,
        downloaded_at=DOWNLOADED_AT,
        content_hash=sha256_bytes(path.read_bytes()),
        version="test",
    )


def source_entry(filename: str, source_type: str, **extra: object) -> SourceEntry:
    """Create one validated local test source entry."""

    return SourceEntry(
        id=f"test-{filename}",
        url=f"https://example.test/{filename}",
        raw_filename=filename,
        source_type=source_type,
        version="test",
        **extra,
    )


def test_microsoft_event_normalization_preserves_provenance() -> None:
    path = FIXTURES / "microsoft_event.html"
    entry = source_entry(path.name, "windows_event_doc", event_id=4625)
    document = normalize_microsoft_document(
        artifact_for(path, "microsoft", entry.source_type), entry
    )
    assert document.event_id == 4625
    assert document.document_id == entry.id
    assert "account logon attempt fails" in document.content
    assert "Navigation" not in document.content
    assert document.effective_or_modified_date == "2025-09-09"
    assert [section["heading"] for section in document.metadata["sections"]] == [
        "Event Description",
        "Security Monitoring Recommendations",
    ]


def test_sysmon_normalization_is_a_separate_source_type() -> None:
    path = FIXTURES / "sysmon.html"
    entry = source_entry(path.name, "sysmon_doc")
    document = normalize_sysmon_document(artifact_for(path, "microsoft", entry.source_type), entry)
    assert document.source_type == "sysmon_doc"
    assert document.metadata["product"] == "sysmon"
    assert "Event ID 3" in document.content
    assert [section["heading"] for section in document.metadata["sections"]] == [
        "Event ID 1: Process creation",
        "Event ID 3: Network connection",
    ]


def test_sigma_rule_remains_one_logical_document() -> None:
    path = FIXTURES / "sigma_rule.yml"
    entry = source_entry(path.name, "sigma_rule")
    document = normalize_sigma_rule(artifact_for(path, "sigma", entry.source_type), entry)
    assert document.sigma_rule_id == "b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c"
    assert document.document_id == f"sigma-{document.sigma_rule_id}"
    assert "condition: selection" in document.content
    assert document.metadata["tags"] == ["attack.execution", "attack.t1059.001"]


def test_mitre_loader_filters_and_preserves_hierarchy() -> None:
    path = FIXTURES / "enterprise_attack.json"
    entry = source_entry(path.name, "mitre_attack", technique_allowlist=["T1059.001"])
    documents = normalize_mitre_bundle(artifact_for(path, "mitre_attack", entry.source_type), entry)
    assert len(documents) == 1
    assert documents[0].technique_id == "T1059"
    assert documents[0].subtechnique_id == "T1059.001"
    assert documents[0].metadata["tactics"] == ["execution"]


def test_raw_store_skips_cached_and_preserves_timestamp_when_unchanged(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, content=b"stable source", request=request, headers={"etag": "v1"}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    store = RawStore(tmp_path, client=client)
    entry = source_entry("source.txt", "test_doc")
    first = store.fetch(entry, source="test", directory="test")
    cached = store.fetch(entry, source="test", directory="test")
    refreshed = store.fetch(entry, source="test", directory="test", refresh=True)
    assert calls == 2
    assert cached.downloaded_at == first.downloaded_at
    assert refreshed.downloaded_at == first.downloaded_at


def test_prepare_pipeline_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    config_dir = project_root / "config"
    config_dir.mkdir()
    config_path = config_dir / "sources.yaml"
    config_path.write_text(
        """microsoft_pages:
  - id: ms-4625
    url: 'https://example.test/ms'
    raw_filename: microsoft_event.html
    source_type: windows_event_doc
    version: test
    event_id: 4625
sysmon_pages:
  - id: sysmon
    url: 'https://example.test/sysmon'
    raw_filename: sysmon.html
    source_type: sysmon_doc
    version: test
sigma_rules:
  - id: sigma
    url: 'https://example.test/sigma'
    raw_filename: sigma_rule.yml
    source_type: sigma_rule
    version: test
mitre_attack:
  id: mitre
  url: 'https://example.test/mitre'
  raw_filename: enterprise_attack.json
  source_type: mitre_attack
  version: test
  technique_allowlist: [T1059.001]
""",
        encoding="utf-8",
    )
    fixture_by_name = {path.name: path for path in FIXTURES.iterdir()}

    def fake_fetch(
        _store: RawStore,
        entry: SourceEntry,
        *,
        source: str,
        directory: str,
        refresh: bool = False,
        offline: bool = False,
    ) -> RawArtifact:
        del refresh, offline
        fixture = fixture_by_name[entry.raw_filename]
        destination = project_root / "data" / "raw" / directory / entry.raw_filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(fixture.read_bytes())
        return artifact_for(destination, source, entry.source_type)

    monkeypatch.setattr(RawStore, "fetch", fake_fetch)
    first = prepare_knowledge(project_root=project_root, config_path=config_path)
    second = prepare_knowledge(project_root=project_root, config_path=config_path)
    assert first.documents == 4
    assert first.output_changed is True
    assert second.output_changed is False
    assert second.added == 0
    assert second.updated == 0
    assert second.unchanged == 4

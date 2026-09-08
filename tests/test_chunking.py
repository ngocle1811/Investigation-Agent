"""Source-aware chunk boundaries, enrichment, and persistence tests."""

from datetime import UTC, datetime
from pathlib import Path

from investigation_agent.ingestion.chunkers import chunk_document
from investigation_agent.ingestion.chunks import load_chunks, prepare_chunks
from investigation_agent.ingestion.microsoft import normalize_microsoft_document
from investigation_agent.ingestion.mitre import normalize_mitre_bundle
from investigation_agent.ingestion.schemas import KnowledgeDocument, RawArtifact, SourceEntry
from investigation_agent.ingestion.sigma import normalize_sigma_rule
from investigation_agent.ingestion.sysmon import normalize_sysmon_document
from investigation_agent.ingestion.utils import sha256_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "ingestion"
DOWNLOADED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _entry(filename: str, source_type: str, **extra: object) -> SourceEntry:
    return SourceEntry(
        id=f"test-{filename}",
        url=f"https://example.test/{filename}",
        raw_filename=filename,
        source_type=source_type,
        version="test",
        **extra,
    )


def _artifact(path: Path, source: str, source_type: str) -> RawArtifact:
    return RawArtifact(
        source=source,
        source_type=source_type,
        url=f"https://example.test/{path.name}",
        path=path,
        downloaded_at=DOWNLOADED_AT,
        content_hash=sha256_bytes(path.read_bytes()),
        version="test",
    )


def _documents() -> list[KnowledgeDocument]:
    microsoft_path = FIXTURES / "microsoft_event.html"
    microsoft_entry = _entry(microsoft_path.name, "windows_event_doc", event_id=4625)
    sysmon_path = FIXTURES / "sysmon.html"
    sysmon_entry = _entry(sysmon_path.name, "sysmon_doc")
    sigma_path = FIXTURES / "sigma_rule.yml"
    sigma_entry = _entry(sigma_path.name, "sigma_rule")
    mitre_path = FIXTURES / "enterprise_attack.json"
    mitre_entry = _entry(
        mitre_path.name, "mitre_attack", technique_allowlist=["T1059.001"]
    )
    return [
        normalize_microsoft_document(
            _artifact(microsoft_path, "microsoft", microsoft_entry.source_type), microsoft_entry
        ),
        normalize_sysmon_document(
            _artifact(sysmon_path, "microsoft", sysmon_entry.source_type), sysmon_entry
        ),
        normalize_sigma_rule(
            _artifact(sigma_path, "sigma", sigma_entry.source_type), sigma_entry
        ),
        *normalize_mitre_bundle(
            _artifact(mitre_path, "mitre_attack", mitre_entry.source_type), mitre_entry
        ),
    ]


def test_microsoft_chunks_preserve_parent_child_boundaries_and_context() -> None:
    chunks = chunk_document(_documents()[0])
    parent, *children = chunks
    assert parent.retrieval_enabled is False
    assert {child.section for child in children} == {
        "Event Description",
        "Security Monitoring Recommendations",
    }
    assert all(child.parent_id == parent.chunk_id for child in children)
    assert all(child.event_id == 4625 for child in children)
    assert all(child.content in child.contextualized_content for child in children)
    assert all(child.hash == child.content_hash for child in children)
    assert all(child.contextualized_content.startswith("Source: Microsoft") for child in children)
    assert [chunk.chunk_id for chunk in chunks] == [
        chunk.chunk_id for chunk in chunk_document(_documents()[0])
    ]


def test_sysmon_chunks_are_grouped_by_event_id() -> None:
    chunks = chunk_document(_documents()[1])
    event_chunks = [chunk for chunk in chunks if chunk.event_id is not None]
    assert {chunk.event_id for chunk in event_chunks} == {1, 3}
    assert all(chunk.parent_id == chunks[0].chunk_id for chunk in event_chunks)
    event_one = next(chunk for chunk in event_chunks if chunk.event_id == 1)
    assert "Event ID: 1" in event_one.contextualized_content


def test_sigma_and_mitre_each_remain_one_enriched_chunk() -> None:
    sigma = chunk_document(_documents()[2])
    mitre = chunk_document(_documents()[3])
    assert len(sigma) == 1
    assert sigma[0].sigma_rule_id == "b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c"
    assert sigma[0].metadata["chunk_role"] == "rule"
    assert len(mitre) == 1
    assert mitre[0].technique_id == "T1059.001"
    assert mitre[0].metadata["parent_technique_id"] == "T1059"
    assert mitre[0].tactic == "execution"


def test_chunk_jsonl_is_valid_and_idempotent(tmp_path: Path) -> None:
    documents_path = tmp_path / "documents.jsonl"
    documents_path.write_text(
        "\n".join(document.model_dump_json() for document in _documents()) + "\n",
        encoding="utf-8",
    )
    chunks_path = tmp_path / "chunks.jsonl"
    first = prepare_chunks(documents_path=documents_path, output_path=chunks_path)
    second = prepare_chunks(documents_path=documents_path, output_path=chunks_path)
    assert first.input_documents == 4
    assert first.parent_chunks == 2
    assert first.output_changed is True
    assert second.output_changed is False
    assert len(load_chunks(chunks_path)) == first.chunks

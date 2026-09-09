"""Checkpoint 5 dense retrieval contracts, golden validation, and metric tests."""

from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from investigation_agent.evaluation.retrieval import (
    GoldenQuery,
    QueryType,
    evaluate_retrieval,
    load_golden_queries,
    recall_at_k,
    reciprocal_rank,
    validate_golden_queries,
    write_retrieval_report,
)
from investigation_agent.ingestion.indexer import sync_chunks
from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.ingestion.utils import sha256_text
from investigation_agent.rag.citations import citations_from_results
from investigation_agent.rag.dense import (
    DenseRetriever,
    KnowledgeFilter,
    KnowledgeSearchResponse,
    RetrievalResult,
    Retriever,
)
from investigation_agent.rag.embeddings import HashEmbeddingProvider
from investigation_agent.rag.query import infer_identifier_filters
from investigation_agent.rag.service import KnowledgeSearchService

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = PROJECT_ROOT / "data" / "golden" / "retrieval_golden.jsonl"


def _chunk(
    chunk_id: str,
    content: str,
    *,
    document_id: str = "doc-1",
    source: str = "microsoft",
    source_type: str = "sysmon_doc",
    event_id: int | None = None,
    parent_id: str | None = None,
    retrieval_enabled: bool = True,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=chunk_id,
        document_id=document_id,
        parent_id=parent_id,
        source=source,
        source_type=source_type,
        title=f"Title {content}",
        section=f"Section {content}",
        content=content,
        contextualized_content=f"Context {content}",
        url="https://example.test/knowledge",
        version="test",
        event_id=event_id,
        content_hash=sha256_text(content),
        retrieval_enabled=retrieval_enabled,
    )


def _result(rank: int, score: float, chunk: KnowledgeChunk) -> RetrievalResult:
    return RetrievalResult.from_chunk(rank=rank, score=score, chunk=chunk)


class CapturingRetriever:
    """Protocol-compatible retriever used to inspect service routing."""

    def __init__(self) -> None:
        self.filters: KnowledgeFilter | None = None

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: KnowledgeFilter | None = None,
    ) -> KnowledgeSearchResponse:
        self.filters = filters
        return KnowledgeSearchResponse(
            query=query,
            filters=filters or KnowledgeFilter(),
            results=[],
        )

    def retrieve_parent(self, parent_id: str) -> KnowledgeChunk | None:
        return None


class StaticSearchService:
    """Return fixed rankings so metric tests do not depend on embeddings."""

    def __init__(self, responses: dict[str, list[RetrievalResult]]) -> None:
        self.responses = responses

    def search(self, query: str, *, top_k: int = 5) -> KnowledgeSearchResponse:
        return KnowledgeSearchResponse(
            query=query,
            filters=KnowledgeFilter(),
            results=self.responses[query][:top_k],
        )


class FixedClock:
    def __init__(self, *values: float) -> None:
        self.values = iter(values)

    def __call__(self) -> float:
        return next(self.values)


def test_dense_retriever_returns_normalized_result_and_parent() -> None:
    client = QdrantClient(":memory:")
    provider = HashEmbeddingProvider(dimension=32)
    parent = _chunk("parent-1", "parent context", retrieval_enabled=False)
    process = _chunk(
        "child-process",
        "process creation command line",
        event_id=1,
        parent_id="parent-1",
    )
    network = _chunk(
        "child-network",
        "network connection destination",
        event_id=3,
        parent_id="parent-1",
    )
    sync_chunks(
        client=client,
        collection="knowledge",
        chunks=[parent, process, network],
        embedding_provider=provider,
    )
    retriever = DenseRetriever(
        client=client,
        collection="knowledge",
        embedding_provider=provider,
    )
    response = retriever.search(
        "process creation",
        top_k=5,
        filters=KnowledgeFilter(source_type="sysmon_doc", event_id=1),
    )
    assert isinstance(retriever, Retriever)
    assert len(response.results) == 1
    result = response.results[0]
    assert result.rank == 1
    assert result.chunk_id == process.chunk_id
    assert result.document_id == process.document_id
    assert result.content == process.content
    assert result.contextualized_content == process.contextualized_content
    assert result.chunk == process
    assert retriever.retrieve_parent("parent-1") == parent
    assert retriever.retrieve_parent("missing-parent") is None


def test_identifier_helpers_are_conservative_and_service_merges_explicit_filters() -> None:
    windows = infer_identifier_filters("Windows Event ID 4625 failed logon")
    assert windows.event_id == 4625
    assert windows.source_type == "windows_event_doc"
    sysmon = infer_identifier_filters("Sysmon Event 22 DNS query")
    assert sysmon.event_id == 22
    assert sysmon.source_type == "sysmon_doc"
    mitre = infer_identifier_filters("MITRE t1059.001 PowerShell")
    assert mitre.technique_id == "T1059.001"
    assert mitre.source_type == "mitre_attack"
    assert (
        infer_identifier_filters("failed authentication on Windows").model_dump(exclude_none=True)
        == {}
    )

    retriever = CapturingRetriever()
    service = KnowledgeSearchService(retriever)
    service.search(
        "Windows Event ID 4625",
        filters=KnowledgeFilter(source="microsoft", source_type="sysmon_doc"),
    )
    assert retriever.filters == KnowledgeFilter(
        source="microsoft", source_type="sysmon_doc", event_id=4625
    )


def test_citation_mapping_preserves_stable_source_identity() -> None:
    first = _result(2, 0.7, _chunk("chunk-2", "network"))
    second = _result(1, 0.8, _chunk("chunk-1", "process"))
    citations = citations_from_results([first, second])
    assert [citation.citation_id for citation in citations] == ["K1", "K2"]
    assert [citation.chunk_id for citation in citations] == ["chunk-1", "chunk-2"]
    assert all(citation.url == "https://example.test/knowledge" for citation in citations)


def _golden(
    query_id: str,
    query: str,
    expected_chunk_id: str,
    *,
    expected_event_id: int | None = None,
) -> GoldenQuery:
    return GoldenQuery(
        query_id=query_id,
        query=query,
        query_type=QueryType.NATURAL_LANGUAGE,
        expected_chunk_ids=[expected_chunk_id],
        expected_document_ids=["doc-1"],
        expected_source_types=["sysmon_doc"],
        expected_event_id=expected_event_id,
        notes="Manually curated test expectation.",
    )


def test_golden_validator_checks_ids_and_corpus_references() -> None:
    process = _chunk("chunk-process", "process", event_id=1)
    network = _chunk("chunk-network", "network", event_id=3)
    query = _golden("RQ001", "find process", "chunk-process", expected_event_id=1)
    summary = validate_golden_queries([query], [process, network])
    assert summary.queries == 1
    assert summary.referenced_chunks == 1
    with pytest.raises(ValueError, match="query IDs must be unique"):
        validate_golden_queries([query, query], [process, network])
    missing = query.model_copy(update={"expected_chunk_ids": ["missing-chunk"]})
    with pytest.raises(ValueError, match="references missing chunks"):
        validate_golden_queries([missing], [process, network])
    wrong_event = query.model_copy(update={"expected_event_id": 99})
    with pytest.raises(ValueError, match="invalid expected Event ID"):
        validate_golden_queries([wrong_event], [process, network])


def test_checked_in_golden_has_fifty_queries_and_four_sources() -> None:
    queries = load_golden_queries(GOLDEN_PATH)
    assert len(queries) == 50
    assert len({query.query_id for query in queries}) == 50
    source_counts: dict[str, int] = {}
    for query in queries:
        for source_type in query.expected_source_types:
            source_counts[source_type] = source_counts.get(source_type, 0) + 1
    assert source_counts == {
        "windows_event_doc": 15,
        "sysmon_doc": 10,
        "mitre_attack": 15,
        "sigma_rule": 10,
    }
    assert {query.query_type for query in queries} == set(QueryType)


def test_recall_and_reciprocal_rank_definitions() -> None:
    assert recall_at_k(1, 1) == 1.0
    assert recall_at_k(3, 1) == 0.0
    assert recall_at_k(3, 3) == 1.0
    assert recall_at_k(None, 5) == 0.0
    assert reciprocal_rank(4) == 0.25
    assert reciprocal_rank(None) == 0.0
    with pytest.raises(ValueError, match="positive"):
        recall_at_k(1, 0)


def test_evaluation_metrics_failures_and_output_are_deterministic(tmp_path: Path) -> None:
    first_chunk = _chunk("chunk-first", "first")
    relevant_chunk = _chunk("chunk-relevant", "relevant")
    queries = [
        _golden("RQ001", "rank two", "chunk-relevant"),
        _golden("RQ002", "missing relevant", "chunk-relevant"),
    ]
    service = StaticSearchService(
        {
            "rank two": [
                _result(1, 0.9, first_chunk),
                _result(2, 0.8, relevant_chunk),
            ],
            "missing relevant": [_result(1, 0.9, first_chunk)],
        }
    )
    kwargs = {
        "queries": queries,
        "service": service,
        "chunks": [first_chunk, relevant_chunk],
        "embedding_model": "test-model",
        "vector_dimension": 32,
        "top_k": 5,
    }
    first_report = evaluate_retrieval(
        **kwargs,
        clock=FixedClock(0.0, 0.01, 1.0, 1.02),
    )
    second_report = evaluate_retrieval(
        **kwargs,
        clock=FixedClock(0.0, 0.01, 1.0, 1.02),
    )
    assert first_report == second_report
    assert first_report.overall.recall_at_1 == 0.0
    assert first_report.overall.recall_at_3 == 0.5
    assert first_report.overall.recall_at_5 == 0.5
    assert first_report.overall.mrr == 0.25
    assert first_report.overall.latency_mean_ms == 15.0
    assert first_report.overall.latency_p50_ms == 15.0
    assert first_report.overall.latency_p95_ms == 19.5
    assert len(first_report.failed_queries) == 1
    assert first_report.failed_queries[0].failure_type == "wrong_section"

    json_path = tmp_path / "baseline.json"
    csv_path = tmp_path / "baseline.csv"
    assert write_retrieval_report(first_report, json_path=json_path, csv_path=csv_path) == (
        True,
        True,
    )
    assert write_retrieval_report(first_report, json_path=json_path, csv_path=csv_path) == (
        False,
        False,
    )
    assert "query_id,query,query_type" in csv_path.read_text(encoding="utf-8")

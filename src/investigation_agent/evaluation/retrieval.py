"""Golden validation, dense retrieval metrics, latency, and failure reporting."""

import csv
import io
import json
import math
from collections import defaultdict
from collections.abc import Callable, Iterable
from enum import StrEnum
from pathlib import Path
from time import perf_counter
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.ingestion.utils import atomic_write_bytes
from investigation_agent.rag.dense import KnowledgeFilter, RetrievalResult
from investigation_agent.rag.service import KnowledgeSearchService


class QueryType(StrEnum):
    """Curated retrieval query families used for breakdown metrics."""

    EXACT_IDENTIFIER = "exact_identifier"
    NATURAL_LANGUAGE = "natural_language"
    SEMANTIC = "semantic"
    DESCRIPTION = "description"
    VOCABULARY_MISMATCH = "vocabulary_mismatch"


class GoldenQuery(BaseModel):
    """One manually curated retrieval expectation."""

    model_config = ConfigDict(extra="forbid")

    query_id: str = Field(pattern=r"^RQ\d{3}$")
    query: str = Field(min_length=3)
    query_type: QueryType
    expected_chunk_ids: list[str] = Field(min_length=1)
    expected_document_ids: list[str] = Field(min_length=1)
    expected_source_types: list[str] = Field(min_length=1)
    expected_event_id: int | None = Field(default=None, ge=0)
    expected_technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    expected_sigma_rule_id: str | None = None
    notes: str = Field(min_length=3)

    @field_validator("expected_chunk_ids", "expected_document_ids", "expected_source_types")
    @classmethod
    def expected_values_must_be_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("golden expected values must be unique")
        return values


class GoldenValidationSummary(BaseModel):
    """Corpus-backed validation counts for an accepted golden dataset."""

    queries: int
    referenced_chunks: int
    referenced_documents: int
    by_source_type: dict[str, int]
    by_query_type: dict[str, int]


class RankedResultSummary(BaseModel):
    """Compact result provenance stored in per-query and failure reports."""

    rank: int
    chunk_id: str
    document_id: str
    source: str
    source_type: str
    title: str
    section: str
    score: float


class QueryEvaluation(BaseModel):
    """Deterministic ranking metrics and latency for one golden query."""

    query_id: str
    query: str
    query_type: QueryType
    expected_source_types: list[str]
    applied_filters: KnowledgeFilter
    first_relevant_rank: int | None = None
    recall_at_1: float
    recall_at_3: float
    recall_at_5: float
    reciprocal_rank: float
    latency_ms: float
    top_results: list[RankedResultSummary]


class FailedQuery(BaseModel):
    """Inspectable retrieval failure with expected and actual top-five evidence."""

    query_id: str
    query: str
    expected_chunk_ids: list[str]
    expected_document_ids: list[str]
    actual_top_5: list[RankedResultSummary]
    failure_type: Literal[
        "wrong_source",
        "wrong_section",
        "semantic_miss",
        "identifier_miss",
        "expected_not_in_top5",
    ]


class MetricSummary(BaseModel):
    """Binary hit-rate recall, MRR, and deterministic latency percentiles."""

    queries: int
    recall_at_1: float
    recall_at_3: float
    recall_at_5: float
    mrr: float
    latency_mean_ms: float
    latency_p50_ms: float
    latency_p95_ms: float


class RetrievalBaselineReport(BaseModel):
    """Complete dense-only baseline report and analysis slices."""

    model_config = ConfigDict(extra="forbid")

    retriever: Literal["dense"] = "dense"
    embedding_model: str
    vector_dimension: int
    retrievable_chunks: int
    total_queries: int
    top_k: int
    metric_definition: str
    overall: MetricSummary
    by_source: dict[str, MetricSummary]
    by_query_type: dict[str, MetricSummary]
    failed_queries: list[FailedQuery]
    queries: list[QueryEvaluation]

    @model_validator(mode="after")
    def counts_must_agree(self) -> Self:
        if self.total_queries != len(self.queries) or self.overall.queries != len(self.queries):
            raise ValueError("retrieval report query counts disagree")
        return self


def load_golden_queries(path: Path) -> list[GoldenQuery]:
    """Load JSONL golden queries with line-specific validation errors."""

    queries: list[GoldenQuery] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            queries.append(GoldenQuery.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid retrieval golden JSONL at line {line_number}") from exc
    return queries


def validate_golden_queries(
    queries: list[GoldenQuery], chunks: list[KnowledgeChunk]
) -> GoldenValidationSummary:
    """Reject missing or inconsistent corpus references without running retrieval."""

    query_ids = [query.query_id for query in queries]
    if len(query_ids) != len(set(query_ids)):
        raise ValueError("golden query IDs must be unique")
    chunk_by_id = {chunk.chunk_id: chunk for chunk in chunks}
    document_ids = {chunk.document_id for chunk in chunks}
    source_types = {chunk.source_type for chunk in chunks}
    event_ids = {chunk.event_id for chunk in chunks if chunk.event_id is not None}
    technique_ids = {chunk.technique_id for chunk in chunks if chunk.technique_id is not None}
    sigma_rule_ids = {chunk.sigma_rule_id for chunk in chunks if chunk.sigma_rule_id is not None}
    for query in queries:
        missing_chunks = set(query.expected_chunk_ids) - set(chunk_by_id)
        if missing_chunks:
            raise ValueError(
                f"{query.query_id} references missing chunks: {sorted(missing_chunks)}"
            )
        if any(
            not chunk_by_id[chunk_id].retrieval_enabled for chunk_id in query.expected_chunk_ids
        ):
            raise ValueError(f"{query.query_id} references a non-retrievable parent chunk")
        missing_documents = set(query.expected_document_ids) - document_ids
        if missing_documents:
            raise ValueError(
                f"{query.query_id} references missing documents: {sorted(missing_documents)}"
            )
        invalid_sources = set(query.expected_source_types) - source_types
        if invalid_sources:
            raise ValueError(
                f"{query.query_id} references invalid source types: {sorted(invalid_sources)}"
            )
        expected_chunks = [chunk_by_id[chunk_id] for chunk_id in query.expected_chunk_ids]
        if any(chunk.document_id not in query.expected_document_ids for chunk in expected_chunks):
            raise ValueError(f"{query.query_id} chunk/document expectations disagree")
        if any(chunk.source_type not in query.expected_source_types for chunk in expected_chunks):
            raise ValueError(f"{query.query_id} chunk/source expectations disagree")
        if query.expected_event_id is not None:
            if query.expected_event_id not in event_ids or not any(
                chunk.event_id == query.expected_event_id for chunk in expected_chunks
            ):
                raise ValueError(f"{query.query_id} has an invalid expected Event ID")
        if query.expected_technique_id is not None:
            if query.expected_technique_id not in technique_ids or not any(
                chunk.technique_id == query.expected_technique_id for chunk in expected_chunks
            ):
                raise ValueError(f"{query.query_id} has an invalid expected MITRE ID")
        if query.expected_sigma_rule_id is not None:
            if query.expected_sigma_rule_id not in sigma_rule_ids or not any(
                chunk.sigma_rule_id == query.expected_sigma_rule_id for chunk in expected_chunks
            ):
                raise ValueError(f"{query.query_id} has an invalid expected Sigma rule ID")
    return GoldenValidationSummary(
        queries=len(queries),
        referenced_chunks=len(
            {chunk_id for query in queries for chunk_id in query.expected_chunk_ids}
        ),
        referenced_documents=len(
            {document_id for query in queries for document_id in query.expected_document_ids}
        ),
        by_source_type=_count_values(
            source for query in queries for source in query.expected_source_types
        ),
        by_query_type=_count_values(query.query_type.value for query in queries),
    )


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: defaultdict[str, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return dict(sorted(counts.items()))


def recall_at_k(first_relevant_rank: int | None, k: int) -> float:
    """Return binary query-level recall: one when any curated chunk appears by rank k."""

    if k < 1:
        raise ValueError("k must be positive")
    return float(first_relevant_rank is not None and first_relevant_rank <= k)


def reciprocal_rank(first_relevant_rank: int | None) -> float:
    """Return reciprocal rank of the first curated chunk, or zero for no hit."""

    return 1.0 / first_relevant_rank if first_relevant_rank else 0.0


def _result_summary(result: RetrievalResult) -> RankedResultSummary:
    return RankedResultSummary(
        rank=result.rank,
        chunk_id=result.chunk_id,
        document_id=result.document_id,
        source=result.source,
        source_type=result.source_type,
        title=result.title,
        section=result.section,
        score=round(result.score, 6),
    )


def _percentile(values: list[float], percentile: float) -> float:
    """Calculate a deterministic linearly interpolated percentile."""

    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _summarize(items: list[QueryEvaluation]) -> MetricSummary:
    if not items:
        return MetricSummary(
            queries=0,
            recall_at_1=0.0,
            recall_at_3=0.0,
            recall_at_5=0.0,
            mrr=0.0,
            latency_mean_ms=0.0,
            latency_p50_ms=0.0,
            latency_p95_ms=0.0,
        )
    count = len(items)
    latencies = [item.latency_ms for item in items]
    return MetricSummary(
        queries=count,
        recall_at_1=round(sum(item.recall_at_1 for item in items) / count, 4),
        recall_at_3=round(sum(item.recall_at_3 for item in items) / count, 4),
        recall_at_5=round(sum(item.recall_at_5 for item in items) / count, 4),
        mrr=round(sum(item.reciprocal_rank for item in items) / count, 4),
        latency_mean_ms=round(sum(latencies) / count, 3),
        latency_p50_ms=round(_percentile(latencies, 0.5), 3),
        latency_p95_ms=round(_percentile(latencies, 0.95), 3),
    )


def _failure_type(
    query: GoldenQuery,
    filters: KnowledgeFilter,
    results: list[RetrievalResult],
) -> str:
    if filters.event_id or filters.technique_id or filters.sigma_rule_id:
        return "identifier_miss"
    if results and not any(
        result.source_type in query.expected_source_types for result in results[:5]
    ):
        return "wrong_source"
    if any(result.document_id in query.expected_document_ids for result in results[:5]):
        return "wrong_section"
    if query.query_type in {
        QueryType.NATURAL_LANGUAGE,
        QueryType.SEMANTIC,
        QueryType.VOCABULARY_MISMATCH,
    }:
        return "semantic_miss"
    return "expected_not_in_top5"


def evaluate_retrieval(
    queries: list[GoldenQuery],
    *,
    service: KnowledgeSearchService,
    chunks: list[KnowledgeChunk],
    embedding_model: str,
    vector_dimension: int,
    top_k: int = 5,
    clock: Callable[[], float] = perf_counter,
) -> RetrievalBaselineReport:
    """Run a dense-only baseline against independently curated expected chunk IDs."""

    if top_k < 5 or top_k > 100:
        raise ValueError("retrieval evaluation top_k must be between 5 and 100")
    validate_golden_queries(queries, chunks)
    evaluations: list[QueryEvaluation] = []
    failures: list[FailedQuery] = []
    for query in queries:
        started = clock()
        response = service.search(query.query, top_k=top_k)
        latency_ms = round((clock() - started) * 1000, 3)
        expected = set(query.expected_chunk_ids)
        relevant_ranks = [result.rank for result in response.results if result.chunk_id in expected]
        first_rank = min(relevant_ranks) if relevant_ranks else None
        result_summaries = [_result_summary(result) for result in response.results]
        evaluation = QueryEvaluation(
            query_id=query.query_id,
            query=query.query,
            query_type=query.query_type,
            expected_source_types=query.expected_source_types,
            applied_filters=response.filters,
            first_relevant_rank=first_rank,
            recall_at_1=recall_at_k(first_rank, 1),
            recall_at_3=recall_at_k(first_rank, 3),
            recall_at_5=recall_at_k(first_rank, 5),
            reciprocal_rank=round(reciprocal_rank(first_rank), 6),
            latency_ms=latency_ms,
            top_results=result_summaries,
        )
        evaluations.append(evaluation)
        if evaluation.recall_at_5 == 0:
            failures.append(
                FailedQuery(
                    query_id=query.query_id,
                    query=query.query,
                    expected_chunk_ids=query.expected_chunk_ids,
                    expected_document_ids=query.expected_document_ids,
                    actual_top_5=result_summaries[:5],
                    failure_type=_failure_type(query, response.filters, response.results),
                )
            )

    by_source: defaultdict[str, list[QueryEvaluation]] = defaultdict(list)
    by_query_type: defaultdict[str, list[QueryEvaluation]] = defaultdict(list)
    for query, evaluation in zip(queries, evaluations, strict=True):
        for source_type in query.expected_source_types:
            by_source[source_type].append(evaluation)
        by_query_type[query.query_type.value].append(evaluation)
    retrievable_chunks = sum(chunk.retrieval_enabled for chunk in chunks)
    return RetrievalBaselineReport(
        embedding_model=embedding_model,
        vector_dimension=vector_dimension,
        retrievable_chunks=retrievable_chunks,
        total_queries=len(queries),
        top_k=top_k,
        metric_definition=(
            "Recall@k is binary per query and equals 1 when any independently curated expected "
            "chunk appears in the first k results; MRR uses the first such chunk."
        ),
        overall=_summarize(evaluations),
        by_source={key: _summarize(value) for key, value in sorted(by_source.items())},
        by_query_type={key: _summarize(value) for key, value in sorted(by_query_type.items())},
        failed_queries=failures,
        queries=evaluations,
    )


def write_retrieval_report(
    report: RetrievalBaselineReport,
    *,
    json_path: Path,
    csv_path: Path,
) -> tuple[bool, bool]:
    """Write full JSON plus one inspectable CSV row per golden query."""

    json_bytes = (
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    buffer = io.StringIO(newline="")
    fieldnames = [
        "query_id",
        "query",
        "query_type",
        "expected_source_types",
        "first_relevant_rank",
        "recall_at_1",
        "recall_at_3",
        "recall_at_5",
        "reciprocal_rank",
        "latency_ms",
        "applied_filters",
        "top_chunk_ids",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for item in report.queries:
        writer.writerow(
            {
                "query_id": item.query_id,
                "query": item.query,
                "query_type": item.query_type.value,
                "expected_source_types": "|".join(item.expected_source_types),
                "first_relevant_rank": item.first_relevant_rank or "",
                "recall_at_1": item.recall_at_1,
                "recall_at_3": item.recall_at_3,
                "recall_at_5": item.recall_at_5,
                "reciprocal_rank": item.reciprocal_rank,
                "latency_ms": item.latency_ms,
                "applied_filters": json.dumps(
                    item.applied_filters.model_dump(exclude_none=True), sort_keys=True
                ),
                "top_chunk_ids": "|".join(result.chunk_id for result in item.top_results),
            }
        )
    csv_bytes = buffer.getvalue().encode("utf-8")
    json_changed = not json_path.exists() or json_path.read_bytes() != json_bytes
    csv_changed = not csv_path.exists() or csv_path.read_bytes() != csv_bytes
    if json_changed:
        atomic_write_bytes(json_path, json_bytes)
    if csv_changed:
        atomic_write_bytes(csv_path, csv_bytes)
    return json_changed, csv_changed

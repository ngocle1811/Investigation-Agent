"""Dense Qdrant retrieval with normalized results and exact metadata filters."""

import logging
from collections.abc import Sequence
from time import perf_counter
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field
from qdrant_client import QdrantClient, models

from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.rag.embeddings import EmbeddingProvider

logger = logging.getLogger(__name__)


class KnowledgeFilter(BaseModel):
    """Supported exact-match filters over indexed knowledge payload."""

    model_config = ConfigDict(extra="forbid")

    document_id: str | None = None
    source: str | None = None
    source_type: str | None = None
    event_id: int | None = None
    sigma_rule_id: str | None = None
    technique_id: str | None = None
    tactic: str | None = None


class RetrievalResult(BaseModel):
    """One flattened, ranked result suitable for citations and downstream consumers."""

    model_config = ConfigDict(extra="forbid")

    rank: int = Field(ge=1)
    score: float
    chunk_id: str
    document_id: str
    parent_id: str | None = None
    source: str
    source_type: str
    title: str
    section: str
    url: str
    event_id: int | None = None
    sigma_rule_id: str | None = None
    technique_id: str | None = None
    tactic: str | None = None
    content: str
    contextualized_content: str
    version: str
    effective_or_modified_date: str | None = None
    content_hash: str
    retrieval_enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_chunk(cls, *, rank: int, score: float, chunk: KnowledgeChunk) -> "RetrievalResult":
        """Normalize a scored Qdrant payload without losing source provenance."""

        return cls(
            rank=rank,
            score=score,
            chunk_id=chunk.chunk_id,
            document_id=chunk.document_id,
            parent_id=chunk.parent_id,
            source=chunk.source,
            source_type=chunk.source_type,
            title=chunk.title,
            section=chunk.section,
            url=chunk.url,
            event_id=chunk.event_id,
            sigma_rule_id=chunk.sigma_rule_id,
            technique_id=chunk.technique_id,
            tactic=chunk.tactic,
            content=chunk.content,
            contextualized_content=chunk.contextualized_content,
            version=chunk.version,
            effective_or_modified_date=chunk.effective_or_modified_date,
            content_hash=chunk.content_hash,
            retrieval_enabled=chunk.retrieval_enabled,
            metadata=chunk.metadata,
        )

    @property
    def chunk(self) -> KnowledgeChunk:
        """Provide the former CP2 chunk view for backward-compatible consumers."""

        return KnowledgeChunk(
            chunk_id=self.chunk_id,
            document_id=self.document_id,
            parent_id=self.parent_id,
            source=self.source,
            source_type=self.source_type,
            title=self.title,
            section=self.section,
            content=self.content,
            contextualized_content=self.contextualized_content,
            url=self.url,
            version=self.version,
            effective_or_modified_date=self.effective_or_modified_date,
            event_id=self.event_id,
            sigma_rule_id=self.sigma_rule_id,
            technique_id=self.technique_id,
            tactic=self.tactic,
            content_hash=self.content_hash,
            retrieval_enabled=self.retrieval_enabled,
            metadata=self.metadata,
        )


class KnowledgeSearchResponse(BaseModel):
    """Stable service/API response for a knowledge query."""

    query: str
    filters: KnowledgeFilter = Field(default_factory=KnowledgeFilter)
    results: list[RetrievalResult]


class Citation(BaseModel):
    """Stable mapping from a local citation label to source provenance."""

    citation_id: str = Field(pattern=r"^K[1-9]\d*$")
    chunk_id: str
    document_id: str
    source: str
    title: str
    section: str
    url: str


@runtime_checkable
class Retriever(Protocol):
    """Replaceable contract for dense, future hybrid, or reranked retrieval."""

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: KnowledgeFilter | None = None,
    ) -> KnowledgeSearchResponse:
        """Return normalized ranked retrieval results."""

    def retrieve_parent(self, parent_id: str) -> KnowledgeChunk | None:
        """Fetch context-only parent payload by stable chunk ID."""


def build_qdrant_filter(filters: KnowledgeFilter | None = None) -> models.Filter:
    """Build the retrieval guard and optional exact metadata conditions."""

    conditions: list[models.Condition] = [
        models.FieldCondition(key="retrieval_enabled", match=models.MatchValue(value=True))
    ]
    if filters:
        for field, value in filters.model_dump(exclude_none=True).items():
            conditions.append(
                models.FieldCondition(key=field, match=models.MatchValue(value=value))
            )
    return models.Filter(must=conditions)


class DenseRetriever:
    """Query one Qdrant collection using the same dense provider used for indexing."""

    def __init__(
        self,
        *,
        client: QdrantClient,
        collection: str,
        embedding_provider: EmbeddingProvider,
    ) -> None:
        self.client = client
        self.collection = collection
        self.embedding_provider = embedding_provider

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: KnowledgeFilter | None = None,
    ) -> KnowledgeSearchResponse:
        """Embed and search child chunks, returning flattened traceable results."""

        if not query.strip():
            raise ValueError("query must not be blank")
        if not 1 <= top_k <= 100:
            raise ValueError("top_k must be between 1 and 100")
        applied_filters = filters or KnowledgeFilter()
        started = perf_counter()
        response = self.client.query_points(
            collection_name=self.collection,
            query=self.embedding_provider.embed_query(query),
            query_filter=build_qdrant_filter(applied_filters),
            limit=top_k,
            with_payload=True,
            with_vectors=False,
        )
        results = [
            RetrievalResult.from_chunk(
                rank=rank,
                score=float(point.score),
                chunk=KnowledgeChunk.model_validate(point.payload),
            )
            for rank, point in enumerate(response.points, 1)
            if point.payload is not None
        ]
        latency_ms = round((perf_counter() - started) * 1000, 3)
        logger.info(
            "dense_knowledge_search",
            extra={
                "query": query,
                "top_k": top_k,
                "filters": applied_filters.model_dump(exclude_none=True),
                "latency_ms": latency_ms,
                "retrieved_chunk_ids": [result.chunk_id for result in results],
                "scores": [round(result.score, 6) for result in results],
            },
        )
        return KnowledgeSearchResponse(
            query=query,
            filters=applied_filters,
            results=results,
        )

    def retrieve_parent(self, parent_id: str) -> KnowledgeChunk | None:
        """Fetch one parent chunk without injecting it into child ranking."""

        if not parent_id.strip():
            raise ValueError("parent_id must not be blank")
        records, _ = self.client.scroll(
            collection_name=self.collection,
            scroll_filter=models.Filter(
                must=[
                    models.FieldCondition(key="chunk_id", match=models.MatchValue(value=parent_id))
                ]
            ),
            limit=1,
            with_payload=True,
            with_vectors=False,
        )
        if not records or records[0].payload is None:
            return None
        return KnowledgeChunk.model_validate(records[0].payload)


# CP2 compatibility names. New code should prefer the singular filter and DenseRetriever.
KnowledgeFilters = KnowledgeFilter
KnowledgeSearchResult = RetrievalResult
DenseKnowledgeRetriever = DenseRetriever


def result_chunk_ids(results: Sequence[RetrievalResult]) -> list[str]:
    """Return result IDs in rank order for logs, evaluation, and tests."""

    return [result.chunk_id for result in sorted(results, key=lambda item: item.rank)]

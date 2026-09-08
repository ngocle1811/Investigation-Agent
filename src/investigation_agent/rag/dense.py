"""Dense Qdrant retrieval with source metadata filters."""

from pydantic import BaseModel, ConfigDict, Field
from qdrant_client import QdrantClient, models

from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.rag.embeddings import EmbeddingProvider


class KnowledgeFilters(BaseModel):
    """Supported exact-match filters over indexed knowledge payload."""

    model_config = ConfigDict(extra="forbid")

    document_id: str | None = None
    source: str | None = None
    source_type: str | None = None
    event_id: int | None = None
    sigma_rule_id: str | None = None
    technique_id: str | None = None
    tactic: str | None = None


class KnowledgeSearchResult(BaseModel):
    """One scored source chunk returned by dense retrieval."""

    score: float
    chunk: KnowledgeChunk


class KnowledgeSearchResponse(BaseModel):
    """Stable API/service response for a knowledge query."""

    query: str
    filters: KnowledgeFilters = Field(default_factory=KnowledgeFilters)
    results: list[KnowledgeSearchResult]


def build_qdrant_filter(filters: KnowledgeFilters | None = None) -> models.Filter:
    """Build the retrieval guard and optional exact metadata conditions."""

    conditions: list[models.Condition] = [
        models.FieldCondition(
            key="retrieval_enabled", match=models.MatchValue(value=True)
        )
    ]
    if filters:
        for field, value in filters.model_dump(exclude_none=True).items():
            conditions.append(
                models.FieldCondition(key=field, match=models.MatchValue(value=value))
            )
    return models.Filter(must=conditions)


class DenseKnowledgeRetriever:
    """Query one Qdrant collection with the same provider used for indexing."""

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
        filters: KnowledgeFilters | None = None,
    ) -> KnowledgeSearchResponse:
        """Return scored, validated chunks while excluding context-only parents."""

        if not query.strip():
            raise ValueError("query must not be blank")
        if not 1 <= top_k <= 100:
            raise ValueError("top_k must be between 1 and 100")
        applied_filters = filters or KnowledgeFilters()
        response = self.client.query_points(
            collection_name=self.collection,
            query=self.embedding_provider.embed_query(query),
            query_filter=build_qdrant_filter(applied_filters),
            limit=top_k,
            with_payload=True,
            with_vectors=False,
        )
        results = [
            KnowledgeSearchResult(
                score=float(point.score),
                chunk=KnowledgeChunk.model_validate(point.payload),
            )
            for point in response.points
            if point.payload is not None
        ]
        return KnowledgeSearchResponse(
            query=query,
            filters=applied_filters,
            results=results,
        )

"""Runtime construction of the configured dense knowledge retriever."""

from functools import lru_cache

from investigation_agent.common.config import get_settings
from investigation_agent.rag.dense import (
    DenseRetriever,
    KnowledgeFilter,
    KnowledgeSearchResponse,
    Retriever,
)
from investigation_agent.rag.embeddings import create_embedding_provider
from investigation_agent.rag.query import infer_identifier_filters, merge_filters
from investigation_agent.storage.vector import get_qdrant_client


@lru_cache
def get_dense_retriever() -> DenseRetriever:
    """Lazily initialize the local model only when knowledge search is used."""

    settings = get_settings()
    provider = create_embedding_provider(
        settings.embedding_provider,
        model_name=settings.embedding_model,
        cache_dir=settings.embedding_cache_dir,
        batch_size=settings.embedding_batch_size,
    )
    return DenseRetriever(
        client=get_qdrant_client(),
        collection=settings.qdrant_collection,
        embedding_provider=provider,
    )


class KnowledgeSearchService:
    """Identifier-aware service over a replaceable retrieval implementation."""

    def __init__(self, retriever: Retriever) -> None:
        self.retriever = retriever

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: KnowledgeFilter | None = None,
        use_identifier_hints: bool = True,
    ) -> KnowledgeSearchResponse:
        """Apply conservative identifier hints, then delegate dense retrieval."""

        inferred = infer_identifier_filters(query) if use_identifier_hints else KnowledgeFilter()
        applied = merge_filters(inferred, filters)
        return self.retriever.search(query, top_k=top_k, filters=applied)


@lru_cache
def get_knowledge_search_service() -> KnowledgeSearchService:
    """Return the runtime search service without coupling consumers to dense retrieval."""

    return KnowledgeSearchService(get_dense_retriever())

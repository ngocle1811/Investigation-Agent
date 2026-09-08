"""Runtime construction of the configured dense knowledge retriever."""

from functools import lru_cache

from investigation_agent.common.config import get_settings
from investigation_agent.rag.dense import DenseKnowledgeRetriever
from investigation_agent.rag.embeddings import create_embedding_provider
from investigation_agent.storage.vector import get_qdrant_client


@lru_cache
def get_dense_retriever() -> DenseKnowledgeRetriever:
    """Lazily initialize the local model only when knowledge search is used."""

    settings = get_settings()
    provider = create_embedding_provider(
        settings.embedding_provider,
        model_name=settings.embedding_model,
        cache_dir=settings.embedding_cache_dir,
        batch_size=settings.embedding_batch_size,
    )
    return DenseKnowledgeRetriever(
        client=get_qdrant_client(),
        collection=settings.qdrant_collection,
        embedding_provider=provider,
    )

"""In-memory Qdrant synchronization, stale cleanup, and filter tests."""

from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from investigation_agent.ingestion.indexer import point_id_for_chunk, sync_chunks
from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.ingestion.utils import sha256_text
from investigation_agent.rag.dense import DenseKnowledgeRetriever, KnowledgeFilters
from investigation_agent.rag.embeddings import EmbeddingProvider


class RecordingEmbeddingProvider(EmbeddingProvider):
    """Tiny semantic fixture that records the exact indexed text."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    @property
    def model_name(self) -> str:
        return "recording"

    @property
    def dimension(self) -> int:
        return 8

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.seen.extend(texts)
        vectors = []
        for text in texts:
            vector = [0.0] * self.dimension
            vector[1 if "network" in text.casefold() else 0] = 1.0
            vectors.append(vector)
        return vectors


def _chunk(
    chunk_id: str,
    document_id: str,
    content: str,
    *,
    retrieval_enabled: bool = True,
    event_id: int | None = None,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=chunk_id,
        document_id=document_id,
        source="microsoft",
        source_type="sysmon_doc",
        title=content,
        section=content,
        content=f"original {content}",
        contextualized_content=f"context enriched {content}",
        url="https://example.test/sysmon",
        version="test",
        event_id=event_id,
        content_hash=sha256_text(f"original {content}"),
        retrieval_enabled=retrieval_enabled,
    )


@pytest.mark.qdrant
def test_sync_is_idempotent_embeds_context_and_cleans_stale_documents(tmp_path: Path) -> None:
    client = QdrantClient(path=str(tmp_path / "qdrant"))
    provider = RecordingEmbeddingProvider()
    original = [
        _chunk("parent", "sysmon", "process parent", retrieval_enabled=False),
        _chunk("event-1", "sysmon", "process creation", event_id=1),
        _chunk("event-3", "sysmon", "network connection", event_id=3),
        _chunk("old-rule", "sigma-old", "process rule"),
    ]
    first = sync_chunks(
        client=client,
        collection="knowledge",
        chunks=original,
        embedding_provider=provider,
        batch_size=2,
    )
    second = sync_chunks(
        client=client,
        collection="knowledge",
        chunks=original,
        embedding_provider=provider,
        batch_size=2,
    )
    assert first.points == second.points == len(original)
    assert provider.seen[: len(original)] == [
        chunk.contextualized_content for chunk in original
    ]

    changed = [_chunk("event-1-v2", "sysmon", "process creation updated", event_id=1)]
    final = sync_chunks(
        client=client,
        collection="knowledge",
        chunks=changed,
        embedding_provider=provider,
    )
    records, _ = client.scroll(collection_name="knowledge", limit=10)
    assert final.points == 1
    assert final.deleted_stale_documents == 1
    assert [str(record.id) for record in records] == [point_id_for_chunk("event-1-v2")]


@pytest.mark.qdrant
def test_dense_search_excludes_parents_and_applies_metadata_filters() -> None:
    client = QdrantClient(":memory:")
    provider = RecordingEmbeddingProvider()
    chunks = [
        _chunk("parent", "sysmon", "process parent", retrieval_enabled=False),
        _chunk("event-1", "sysmon", "process creation", event_id=1),
        _chunk("event-3", "sysmon", "network connection", event_id=3),
    ]
    sync_chunks(
        client=client,
        collection="knowledge",
        chunks=chunks,
        embedding_provider=provider,
    )
    retriever = DenseKnowledgeRetriever(
        client=client,
        collection="knowledge",
        embedding_provider=provider,
    )
    process = retriever.search("process creation", top_k=3)
    assert process.results[0].chunk.chunk_id == "event-1"
    assert all(result.chunk.retrieval_enabled for result in process.results)
    network = retriever.search(
        "process creation",
        filters=KnowledgeFilters(source_type="sysmon_doc", event_id=3),
    )
    assert [result.chunk.chunk_id for result in network.results] == ["event-3"]

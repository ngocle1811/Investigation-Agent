"""Idempotent synchronization of prepared knowledge chunks into Qdrant."""

import uuid
from collections.abc import Iterable
from typing import TypeVar

from qdrant_client import QdrantClient, models

from investigation_agent.ingestion.schemas import IndexingSummary, KnowledgeChunk
from investigation_agent.rag.embeddings import EmbeddingProvider

T = TypeVar("T")

_PAYLOAD_INDEXES = {
    "document_id": models.PayloadSchemaType.KEYWORD,
    "source": models.PayloadSchemaType.KEYWORD,
    "source_type": models.PayloadSchemaType.KEYWORD,
    "event_id": models.PayloadSchemaType.INTEGER,
    "sigma_rule_id": models.PayloadSchemaType.KEYWORD,
    "technique_id": models.PayloadSchemaType.KEYWORD,
    "tactic": models.PayloadSchemaType.KEYWORD,
    "retrieval_enabled": models.PayloadSchemaType.BOOL,
}


def point_id_for_chunk(chunk_id: str) -> str:
    """Map a deterministic chunk ID to a Qdrant-compatible deterministic UUID."""

    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"investigation-agent:{chunk_id}"))


def _batches(items: list[T], size: int) -> Iterable[list[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _collection_vector_size(client: QdrantClient, collection: str) -> int:
    info = client.get_collection(collection)
    vectors = info.config.params.vectors
    if not isinstance(vectors, models.VectorParams):
        raise ValueError(f"Collection {collection} must use one unnamed dense vector")
    return vectors.size


def _ensure_collection(client: QdrantClient, collection: str, vector_size: int) -> None:
    if not client.collection_exists(collection):
        client.create_collection(
            collection_name=collection,
            vectors_config=models.VectorParams(size=vector_size, distance=models.Distance.COSINE),
        )
        for field_name, field_schema in _PAYLOAD_INDEXES.items():
            client.create_payload_index(
                collection_name=collection,
                field_name=field_name,
                field_schema=field_schema,
                wait=True,
            )
        return
    existing_size = _collection_vector_size(client, collection)
    if existing_size != vector_size:
        raise ValueError(
            f"Collection {collection} vector size is {existing_size}, expected {vector_size}"
        )


def _existing_document_ids(client: QdrantClient, collection: str) -> set[str]:
    document_ids: set[str] = set()
    offset = None
    while True:
        records, offset = client.scroll(
            collection_name=collection,
            limit=256,
            offset=offset,
            with_payload=["document_id"],
            with_vectors=False,
        )
        document_ids.update(
            str(record.payload["document_id"])
            for record in records
            if record.payload and record.payload.get("document_id")
        )
        if offset is None:
            break
    return document_ids


def _delete_document(client: QdrantClient, collection: str, document_id: str) -> None:
    client.delete(
        collection_name=collection,
        points_selector=models.Filter(
            must=[
                models.FieldCondition(
                    key="document_id", match=models.MatchValue(value=document_id)
                )
            ]
        ),
        wait=True,
    )


def sync_chunks(
    *,
    client: QdrantClient,
    collection: str,
    chunks: list[KnowledgeChunk],
    embedding_provider: EmbeddingProvider,
    batch_size: int = 32,
) -> IndexingSummary:
    """Replace current documents and remove stale documents without duplicate points."""

    if not chunks:
        raise ValueError("Cannot index an empty knowledge corpus")
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    vectors: list[list[float]] = []
    for batch in _batches(chunks, batch_size):
        vectors.extend(
            embedding_provider.embed_documents(
                [chunk.contextualized_content for chunk in batch]
            )
        )
    _ensure_collection(client, collection, embedding_provider.dimension)

    current_document_ids = {chunk.document_id for chunk in chunks}
    stale_document_ids = _existing_document_ids(client, collection) - current_document_ids
    for document_id in sorted(stale_document_ids | current_document_ids):
        _delete_document(client, collection, document_id)

    points = [
        models.PointStruct(
            id=point_id_for_chunk(chunk.chunk_id),
            vector=vector,
            payload=chunk.model_dump(mode="json"),
        )
        for chunk, vector in zip(chunks, vectors, strict=True)
    ]
    for batch in _batches(points, batch_size):
        client.upsert(collection_name=collection, points=batch, wait=True)
    point_count = client.count(collection_name=collection, exact=True).count
    return IndexingSummary(
        collection=collection,
        documents=len(current_document_ids),
        chunks=len(chunks),
        points=point_count,
        deleted_stale_documents=len(stale_document_ids),
        vector_size=embedding_provider.dimension,
    )

"""Persistence for deterministic source-aware knowledge chunks."""

import json
from collections import Counter
from pathlib import Path

from investigation_agent.ingestion.chunkers import chunk_documents
from investigation_agent.ingestion.schemas import ChunkingSummary, KnowledgeChunk, KnowledgeDocument
from investigation_agent.ingestion.utils import atomic_write_bytes


def load_documents(path: Path) -> list[KnowledgeDocument]:
    """Load and validate normalized document JSONL."""

    documents: list[KnowledgeDocument] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            documents.append(KnowledgeDocument.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid document JSONL at line {line_number}") from exc
    return documents


def load_chunks(path: Path) -> list[KnowledgeChunk]:
    """Load and validate prepared chunk JSONL."""

    chunks: list[KnowledgeChunk] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            chunks.append(KnowledgeChunk.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid chunk JSONL at line {line_number}") from exc
    return chunks


def prepare_chunks(*, documents_path: Path, output_path: Path) -> ChunkingSummary:
    """Create and persist deterministic chunks from normalized documents."""

    documents = load_documents(documents_path)
    chunks = chunk_documents(documents)
    lines = [chunk.model_dump_json(exclude_none=False) for chunk in chunks]
    serialized = ("\n".join(lines) + "\n").encode("utf-8")
    output_changed = not output_path.exists() or output_path.read_bytes() != serialized
    if output_changed:
        atomic_write_bytes(output_path, serialized)
    counts = Counter(chunk.source_type for chunk in chunks)
    return ChunkingSummary(
        input_documents=len(documents),
        chunks=len(chunks),
        parent_chunks=sum(not chunk.retrieval_enabled for chunk in chunks),
        retrievable_chunks=sum(chunk.retrieval_enabled for chunk in chunks),
        by_source_type=dict(sorted(counts.items())),
        output_path=output_path.as_posix(),
        output_changed=output_changed,
    )


def chunking_summary_as_json(summary: ChunkingSummary) -> str:
    """Render a stable human-readable chunking summary."""

    return json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2)

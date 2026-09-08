"""Prepare, embed, and index the curated security knowledge corpus."""

import argparse
import json
from pathlib import Path

from investigation_agent.common.config import get_settings
from investigation_agent.ingestion.chunks import load_chunks, prepare_chunks
from investigation_agent.ingestion.indexer import sync_chunks
from investigation_agent.ingestion.pipeline import prepare_knowledge
from investigation_agent.rag.embeddings import create_embedding_provider
from investigation_agent.storage.vector import get_qdrant_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    """Parse ingestion command-line flags."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Download/load and normalize sources without embedding or Qdrant indexing.",
    )
    parser.add_argument("--refresh", action="store_true", help="Re-fetch cached remote sources.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use raw cached sources only and fail clearly if one is missing.",
    )
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "config" / "sources.yaml")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "knowledge" / "documents.jsonl",
    )
    parser.add_argument(
        "--chunks-output",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "knowledge" / "chunks.jsonl",
    )
    return parser.parse_args()


def main() -> int:
    """Run deterministic preparation and optionally synchronize Qdrant."""

    args = parse_args()
    document_summary = prepare_knowledge(
        project_root=PROJECT_ROOT,
        config_path=args.config,
        output_path=args.output,
        refresh=args.refresh,
        offline=args.offline,
    )
    if args.prepare_only:
        print(json.dumps({"documents": document_summary.model_dump(mode="json")}, indent=2))
        return 0

    chunk_summary = prepare_chunks(documents_path=args.output, output_path=args.chunks_output)
    settings = get_settings()
    provider = create_embedding_provider(
        settings.embedding_provider,
        model_name=settings.embedding_model,
        cache_dir=settings.embedding_cache_dir,
        batch_size=settings.embedding_batch_size,
    )
    index_summary = sync_chunks(
        client=get_qdrant_client(),
        collection=settings.qdrant_collection,
        chunks=load_chunks(args.chunks_output),
        embedding_provider=provider,
        batch_size=settings.embedding_batch_size,
    )
    print(
        json.dumps(
            {
                "documents": document_summary.model_dump(mode="json"),
                "chunks": chunk_summary.model_dump(mode="json"),
                "index": index_summary.model_dump(mode="json"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

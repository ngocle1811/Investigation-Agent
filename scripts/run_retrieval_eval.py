"""Evaluate the dense retrieval baseline against the curated golden dataset."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from investigation_agent.common.config import get_settings  # noqa: E402
from investigation_agent.common.logging import configure_logging  # noqa: E402
from investigation_agent.evaluation.retrieval import (  # noqa: E402
    evaluate_retrieval,
    load_golden_queries,
    validate_golden_queries,
    write_retrieval_report,
)
from investigation_agent.ingestion.chunks import load_chunks  # noqa: E402
from investigation_agent.rag.service import (  # noqa: E402
    KnowledgeSearchService,
    get_dense_retriever,
)


def parse_args() -> argparse.Namespace:
    """Parse golden, corpus, ranking, and artifact paths."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--golden",
        type=Path,
        default=PROJECT_ROOT / "data" / "golden" / "retrieval_golden.jsonl",
    )
    parser.add_argument(
        "--chunks",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "knowledge" / "chunks.jsonl",
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "artifacts" / "eval" / "retrieval_baseline.json",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=PROJECT_ROOT / "artifacts" / "eval" / "retrieval_baseline.csv",
    )
    return parser.parse_args()


def main() -> int:
    """Validate independent expectations, run dense search, and persist metrics."""

    args = parse_args()
    settings = get_settings()
    configure_logging(settings.log_level)
    chunks = load_chunks(args.chunks)
    golden = load_golden_queries(args.golden)
    validation = validate_golden_queries(golden, chunks)
    retriever = get_dense_retriever()
    # Warm one query embedding so measured latency reflects steady-state retrieval rather than
    # one-time lazy model initialization. This text is never searched or used as golden data.
    retriever.embedding_provider.embed_query("dense retrieval baseline warmup")
    report = evaluate_retrieval(
        golden,
        service=KnowledgeSearchService(retriever),
        chunks=chunks,
        embedding_model=retriever.embedding_provider.model_name,
        vector_dimension=retriever.embedding_provider.dimension,
        top_k=args.top_k,
    )
    json_changed, csv_changed = write_retrieval_report(
        report,
        json_path=args.output,
        csv_path=args.csv_output,
    )
    console = {
        "golden_validation": validation.model_dump(mode="json"),
        "embedding_model": report.embedding_model,
        "vector_dimension": report.vector_dimension,
        "retrievable_chunks": report.retrievable_chunks,
        "total_queries": report.total_queries,
        "overall": report.overall.model_dump(mode="json"),
        "failed_queries": len(report.failed_queries),
        "output": str(args.output),
        "csv_output": str(args.csv_output),
        "json_changed": json_changed,
        "csv_changed": csv_changed,
    }
    print(json.dumps(console, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

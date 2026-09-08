"""Download and normalize the curated security knowledge corpus."""

import argparse
from pathlib import Path

from investigation_agent.ingestion.pipeline import prepare_knowledge, summary_as_json

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
    return parser.parse_args()


def main() -> int:
    """Run Checkpoint 1 preparation; indexing is intentionally deferred."""

    args = parse_args()
    if not args.prepare_only:
        raise SystemExit("Checkpoint 2 indexing is not implemented; use --prepare-only")
    summary = prepare_knowledge(
        project_root=PROJECT_ROOT,
        config_path=args.config,
        output_path=args.output,
        refresh=args.refresh,
        offline=args.offline,
    )
    print(summary_as_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

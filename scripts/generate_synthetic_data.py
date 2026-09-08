"""Generate deterministic synthetic security incident cases for evaluation."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from investigation_agent.events.scenario_templates import (  # noqa: E402
    configured_mitre_ids,
    load_scenario_catalog,
)
from investigation_agent.events.synthetic_generator import (  # noqa: E402
    generate_dataset,
    write_dataset,
)


def parse_args() -> argparse.Namespace:
    """Parse deterministic dataset generation options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--variants", type=int, default=3)
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "config" / "synthetic_scenarios.yaml",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=PROJECT_ROOT / "config" / "sources.yaml",
        help="Knowledge-source config whose MITRE allowlist constrains template mappings.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "data" / "synthetic" / "incidents.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=None,
        help="Defaults to summary.json beside --output.",
    )
    return parser.parse_args()


def main() -> int:
    """Validate templates, generate cases, and write stable output files."""

    args = parse_args()
    summary_path = args.summary_output or args.output.with_name("summary.json")
    catalog = load_scenario_catalog(
        args.config,
        allowed_mitre_ids=configured_mitre_ids(args.sources),
    )
    cases, summary = generate_dataset(catalog, seed=args.seed, variants=args.variants)
    dataset_changed, summary_changed = write_dataset(
        cases,
        summary,
        output_path=args.output,
        summary_path=summary_path,
    )
    print(
        json.dumps(
            {
                **summary.model_dump(mode="json"),
                "output": str(args.output),
                "summary_output": str(summary_path),
                "dataset_changed": dataset_changed,
                "summary_changed": summary_changed,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

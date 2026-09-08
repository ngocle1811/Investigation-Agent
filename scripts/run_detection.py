"""Run deterministic detection, correlation, behavior aggregation, and case building."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from investigation_agent.detection.config import load_detection_config  # noqa: E402
from investigation_agent.detection.pipeline import (  # noqa: E402
    process_incidents,
    write_detection_outputs,
)
from investigation_agent.events.scenario_templates import (  # noqa: E402
    configured_mitre_ids,
)
from investigation_agent.events.synthetic_generator import load_dataset  # noqa: E402


def parse_args() -> argparse.Namespace:
    """Parse detection pipeline inputs and deterministic export options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=PROJECT_ROOT / "data" / "synthetic" / "incidents.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "incidents" / "cases.jsonl",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=None,
        help="Defaults to detection_summary.json beside --output.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "config" / "correlation_rules.yaml",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=PROJECT_ROOT / "config" / "sources.yaml",
        help="Knowledge config whose MITRE allowlist constrains detection-rule mappings.",
    )
    parser.add_argument(
        "--include-ground-truth",
        action="store_true",
        help="Attach evaluation-only expected rules to exported cases.",
    )
    return parser.parse_args()


def main() -> int:
    """Process the input dataset and emit inspectable deterministic artifacts."""

    args = parse_args()
    summary_path = args.summary_output or args.output.with_name("detection_summary.json")
    config = load_detection_config(
        args.config,
        allowed_mitre_ids=configured_mitre_ids(args.sources),
    )
    incidents = load_dataset(args.input)
    cases, summary = process_incidents(
        incidents,
        config,
        include_ground_truth=args.include_ground_truth,
    )
    cases_changed, summary_changed = write_detection_outputs(
        cases,
        summary,
        output_path=args.output,
        summary_path=summary_path,
    )
    console = {
        key: value
        for key, value in summary.model_dump(mode="json").items()
        if key not in {"comparisons", "failures"}
    }
    console.update(
        {
            "failure_count": len(summary.failures),
            "output": str(args.output),
            "summary_output": str(summary_path),
            "cases_changed": cases_changed,
            "summary_changed": summary_changed,
        }
    )
    print(json.dumps(console, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

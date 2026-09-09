"""Run one grounded investigation or all three deterministic demo cases."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from investigation_agent.common.config import get_settings  # noqa: E402
from investigation_agent.common.logging import configure_logging  # noqa: E402
from investigation_agent.detection.config import load_detection_config  # noqa: E402
from investigation_agent.detection.pipeline import load_investigation_cases  # noqa: E402
from investigation_agent.evaluation.investigation import (  # noqa: E402
    evaluate_investigation_run,
    load_investigation_demo_cases,
    summarize_investigation_evaluations,
    validate_investigation_demo_cases,
)
from investigation_agent.events.scenario_templates import (  # noqa: E402
    configured_mitre_ids,
)
from investigation_agent.ingestion.utils import atomic_write_bytes  # noqa: E402
from investigation_agent.investigation.service import (  # noqa: E402
    create_runtime_investigation_service,
)


def parse_args() -> argparse.Namespace:
    """Parse case selection, local inputs, provider override, and JSON output options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", default="INC-S02-V01")
    parser.add_argument("--behavior-id")
    parser.add_argument("--demo-all", action="store_true")
    parser.add_argument("--top-k", type=int)
    parser.add_argument("--llm-provider", choices=["mock", "openai", "gemini"])
    parser.add_argument(
        "--cases",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "incidents" / "cases.jsonl",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=PROJECT_ROOT / "config" / "correlation_rules.yaml",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=PROJECT_ROOT / "config" / "sources.yaml",
    )
    parser.add_argument(
        "--demo-fixtures",
        type=Path,
        default=PROJECT_ROOT / "data" / "golden" / "investigation_demo_cases.json",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def _run_payload(run) -> dict:
    return {
        "investigation_case": {
            "case_id": run.context.case_id,
            "candidate_behavior": run.context.candidate_behavior.model_dump(mode="json"),
            "rule_matches": [item.model_dump(mode="json") for item in run.context.rule_matches],
            "rule_context": [item.model_dump(mode="json") for item in run.context.rule_context],
            "related_events": [item.model_dump(mode="json") for item in run.context.related_events],
        },
        "retrieval_query": run.context.retrieval_query,
        "supplemental_retrieval_queries": run.context.supplemental_retrieval_queries,
        "retrieved_knowledge": [
            {
                "citation_id": item.citation_id,
                "rank": item.rank,
                "score": round(item.score, 6),
                "chunk_id": item.chunk_id,
                "document_id": item.document_id,
                "source": item.source,
                "source_type": item.source_type,
                "title": item.title,
                "section": item.section,
                "url": item.url,
                "technique_id": item.technique_id,
                "sigma_rule_id": item.sigma_rule_id,
                "metadata": item.metadata,
            }
            for item in run.context.retrieved_knowledge
        ],
        "report": run.report.model_dump(mode="json"),
        "grounding": run.grounding.model_dump(mode="json"),
        "llm": {
            "provider": run.llm_provider,
            "model": run.llm_model,
            "latency_ms": run.llm_latency_ms,
            "prompt_tokens": run.prompt_tokens,
            "completion_tokens": run.completion_tokens,
        },
    }


def _evaluation_payload(evaluation, run) -> dict:
    """Expose reviewer-facing field names without changing deterministic evaluation models."""

    return {
        "case_id": evaluation.case_id,
        "schema_valid": evaluation.report_schema_valid,
        "evidence_refs_valid": evaluation.all_evidence_refs_exist,
        "knowledge_refs_valid": evaluation.all_knowledge_refs_exist,
        "key_events_cited": evaluation.expected_key_events_cited,
        "timeline_refs_valid": evaluation.timeline_event_ids_belong_to_case,
        "timestamps_valid": evaluation.timeline_timestamps_match_evidence,
        "hallucinated_event_ids": run.grounding.unknown_event_ids,
        "expected_mitre_covered": evaluation.expected_mitre_coverage,
        "recommended_actions_present": evaluation.recommended_action_present,
        "overall_pass": evaluation.passed,
        "missing_key_event_ids": evaluation.missing_key_event_ids,
        "missing_mitre_techniques": evaluation.missing_mitre_techniques,
    }


def main() -> int:
    """Execute dense retrieval, structured investigation, and deterministic grounding checks."""

    args = parse_args()
    settings = get_settings()
    if args.llm_provider:
        settings = settings.model_copy(update={"llm_provider": args.llm_provider})
    configure_logging(settings.log_level)
    service = create_runtime_investigation_service(
        settings=settings,
        cases_path=args.cases,
        rules_path=args.rules,
        sources_path=args.sources,
        top_k=args.top_k,
    )
    exit_code = 0
    if args.demo_all:
        cases = load_investigation_cases(args.cases)
        config = load_detection_config(
            args.rules,
            allowed_mitre_ids=configured_mitre_ids(args.sources),
        )
        demos = load_investigation_demo_cases(args.demo_fixtures)
        validate_investigation_demo_cases(demos, cases, config)
        runs = [
            service.investigate_case(demo.case_id, behavior_id=demo.behavior_id) for demo in demos
        ]
        evaluations = [
            evaluate_investigation_run(run, demo) for run, demo in zip(runs, demos, strict=True)
        ]
        summary = summarize_investigation_evaluations(evaluations)
        exit_code = int(summary.failed_cases > 0)
        payload = {
            "provider": service.llm.provider,
            "model": service.llm.model,
            "summary": {
                "total_cases": summary.total_cases,
                "passed_cases": summary.passed_cases,
                "failed_cases": summary.failed_cases,
            },
            "cases": [
                {**_run_payload(run), "evaluation": _evaluation_payload(evaluation, run)}
                for run, evaluation in zip(runs, evaluations, strict=True)
            ],
        }
    else:
        run = service.investigate_case(args.case_id, behavior_id=args.behavior_id)
        payload = _run_payload(run)
    output = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if args.output:
        atomic_write_bytes(args.output, output)
        print(json.dumps({"output": str(args.output)}, ensure_ascii=False))
    else:
        sys.stdout.buffer.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

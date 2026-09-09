"""Search the dense security-knowledge baseline and print traceable ranked results."""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from investigation_agent.common.logging import configure_logging  # noqa: E402
from investigation_agent.rag.citations import citations_from_results  # noqa: E402
from investigation_agent.rag.dense import KnowledgeFilter  # noqa: E402
from investigation_agent.rag.service import (  # noqa: E402
    get_dense_retriever,
    get_knowledge_search_service,
)


def parse_args() -> argparse.Namespace:
    """Parse query, ranking, and exact metadata filter options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--source")
    parser.add_argument("--source-type")
    parser.add_argument("--event-id", type=int)
    parser.add_argument("--technique-id")
    parser.add_argument("--sigma-rule-id")
    parser.add_argument(
        "--no-identifier-hints",
        action="store_true",
        help="Disable deterministic Event/MITRE/Sigma identifier inference.",
    )
    parser.add_argument(
        "--show-parent",
        action="store_true",
        help="Fetch and show the parent chunk ID for child results when available.",
    )
    return parser.parse_args()


def main() -> int:
    """Run one dense query and render ranked source details."""

    args = parse_args()
    configure_logging()
    filters = KnowledgeFilter(
        source=args.source,
        source_type=args.source_type,
        event_id=args.event_id,
        technique_id=args.technique_id.upper() if args.technique_id else None,
        sigma_rule_id=args.sigma_rule_id.lower() if args.sigma_rule_id else None,
    )
    service = get_knowledge_search_service()
    response = service.search(
        args.query,
        top_k=args.top_k,
        filters=filters,
        use_identifier_hints=not args.no_identifier_hints,
    )
    citations = citations_from_results(response.results)
    print(f"Query: {response.query}")
    print(f"Filters: {response.filters.model_dump(exclude_none=True)}")
    if not response.results:
        print("No results.")
        return 0
    retriever = get_dense_retriever()
    for result, citation in zip(response.results, citations, strict=True):
        print()
        print(f"{result.rank}. [{citation.citation_id}] [{result.source}] {result.title}")
        print(f"   section: {result.section}")
        print(f"   score: {result.score:.6f}")
        print(f"   chunk_id: {result.chunk_id}")
        print(f"   document_id: {result.document_id}")
        print(f"   URL: {result.url}")
        if args.show_parent and result.parent_id:
            parent = retriever.retrieve_parent(result.parent_id)
            parent_label = parent.chunk_id if parent else "not found"
            print(f"   parent: {parent_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

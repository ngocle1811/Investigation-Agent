"""Citation mapping for traceable knowledge retrieval results."""

from collections.abc import Sequence

from investigation_agent.rag.dense import Citation, RetrievalResult


def citations_from_results(results: Sequence[RetrievalResult]) -> list[Citation]:
    """Map ranked results to local K1..Kn labels with stable source provenance."""

    ordered = sorted(results, key=lambda result: result.rank)
    return [
        Citation(
            citation_id=f"K{index}",
            chunk_id=result.chunk_id,
            document_id=result.document_id,
            source=result.source,
            title=result.title,
            section=result.section,
            url=result.url,
        )
        for index, result in enumerate(ordered, 1)
    ]

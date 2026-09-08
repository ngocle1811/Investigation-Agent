"""Knowledge search API backed by source-aware Qdrant chunks."""

from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.concurrency import run_in_threadpool

from investigation_agent.rag.dense import KnowledgeFilters, KnowledgeSearchResponse
from investigation_agent.rag.service import get_dense_retriever

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge(
    q: Annotated[str, Query(min_length=1, description="Natural-language knowledge query")],
    top_k: Annotated[int, Query(ge=1, le=100)] = 5,
    document_id: str | None = None,
    source: str | None = None,
    source_type: str | None = None,
    event_id: int | None = None,
    sigma_rule_id: str | None = None,
    technique_id: str | None = None,
    tactic: str | None = None,
) -> KnowledgeSearchResponse:
    """Search retrievable chunks with optional exact-match metadata filters."""

    filters = KnowledgeFilters(
        document_id=document_id,
        source=source,
        source_type=source_type,
        event_id=event_id,
        sigma_rule_id=sigma_rule_id,
        technique_id=technique_id,
        tactic=tactic,
    )
    retriever = get_dense_retriever()
    return await run_in_threadpool(retriever.search, q, top_k=top_k, filters=filters)

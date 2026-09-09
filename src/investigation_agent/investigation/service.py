"""One obvious orchestration service for the grounded investigation vertical slice."""

import logging
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from investigation_agent.common.config import Settings, get_settings
from investigation_agent.detection.config import load_detection_config
from investigation_agent.detection.pipeline import load_investigation_cases
from investigation_agent.detection.schemas import DetectionConfig, InvestigationCase
from investigation_agent.events.scenario_templates import configured_mitre_ids
from investigation_agent.investigation.assembler import InvestigationCaseAssembler
from investigation_agent.investigation.grounding import require_grounded_report
from investigation_agent.investigation.llm import (
    StructuredInvestigationLLM,
    create_investigation_llm,
)
from investigation_agent.investigation.prompts import (
    INVESTIGATION_SYSTEM_PROMPT,
    build_investigation_prompt,
)
from investigation_agent.investigation.schemas import (
    InvestigationContext,
    InvestigationKnowledge,
    InvestigationRun,
)
from investigation_agent.rag.citations import citations_from_results
from investigation_agent.rag.dense import KnowledgeFilter, Retriever
from investigation_agent.rag.service import get_dense_retriever

logger = logging.getLogger(__name__)


class InvestigationService:
    """Evidence assembly, dense retrieval, structured generation, and fail-closed validation."""

    def __init__(
        self,
        *,
        cases: Sequence[InvestigationCase],
        detection_config: DetectionConfig,
        retriever: Retriever,
        llm: StructuredInvestigationLLM,
        top_k: int = 5,
    ) -> None:
        if not 1 <= top_k <= 20:
            raise ValueError("investigation top_k must be between 1 and 20")
        self.cases = {case.case_id: case for case in cases}
        if len(self.cases) != len(cases):
            raise ValueError("investigation cases must have unique case IDs")
        self.assembler = InvestigationCaseAssembler(detection_config)
        self.retriever = retriever
        self.llm = llm
        self.top_k = top_k

    def investigate_case(
        self,
        case_id: str,
        *,
        behavior_id: str | None = None,
    ) -> InvestigationRun:
        """Investigate one existing behavior without asking the model to detect raw events."""

        case = self.cases.get(case_id)
        if case is None:
            raise ValueError(f"investigation case not found: {case_id}")
        trace_id = str(uuid4())
        evidence = self.assembler.assemble(case, behavior_id=behavior_id)
        search = self.retriever.search(evidence.retrieval_query, top_k=self.top_k)
        results = list(search.results)
        known_chunks = {result.chunk_id for result in results}
        technique_ids = list(
            dict.fromkeys(
                technique for rule in evidence.rule_context for technique in rule.mitre_techniques
            )
        )
        for technique_id, query in zip(
            technique_ids,
            evidence.supplemental_retrieval_queries,
            strict=True,
        ):
            supplemental = self.retriever.search(
                query,
                top_k=1,
                filters=KnowledgeFilter(
                    source_type="mitre_attack",
                    technique_id=technique_id,
                ),
            )
            for result in supplemental.results:
                if result.chunk_id not in known_chunks:
                    results.append(result)
                    known_chunks.add(result.chunk_id)
        results = [
            result.model_copy(update={"rank": rank}) for rank, result in enumerate(results, 1)
        ]
        if not results:
            raise ValueError(f"no security knowledge retrieved for case {case_id}")
        citations = citations_from_results(results)
        knowledge = [
            InvestigationKnowledge(
                citation_id=citation.citation_id,
                rank=result.rank,
                score=result.score,
                chunk_id=result.chunk_id,
                document_id=result.document_id,
                source=result.source,
                source_type=result.source_type,
                title=result.title,
                section=result.section,
                url=result.url,
                technique_id=result.technique_id,
                sigma_rule_id=result.sigma_rule_id,
                content=result.contextualized_content,
                metadata=result.metadata,
            )
            for result, citation in zip(results, citations, strict=True)
        ]
        context = InvestigationContext(
            **evidence.model_dump(),
            retrieved_knowledge=knowledge,
        )
        generation = self.llm.generate(
            system_prompt=INVESTIGATION_SYSTEM_PROMPT,
            user_prompt=build_investigation_prompt(context),
            context=context,
        )
        validation = require_grounded_report(generation.report, context)
        logger.info(
            "investigation_completed",
            extra={
                "trace_id": trace_id,
                "case_id": case_id,
                "behavior_id": evidence.candidate_behavior.behavior_id,
                "retrieval_query": evidence.retrieval_query,
                "supplemental_retrieval_queries": evidence.supplemental_retrieval_queries,
                "retrieved_chunk_ids": [item.chunk_id for item in knowledge],
                "retrieval_scores": [round(item.score, 6) for item in knowledge],
                "rule_matches": [match.match_id for match in evidence.rule_matches],
                "llm_provider": generation.provider,
                "llm_model": generation.model,
                "prompt_tokens": generation.prompt_tokens,
                "completion_tokens": generation.completion_tokens,
                "llm_latency_ms": generation.latency_ms,
                "grounding_valid": validation.valid,
            },
        )
        return InvestigationRun(
            context=context,
            report=generation.report,
            grounding=validation,
            llm_provider=generation.provider,
            llm_model=generation.model,
            llm_latency_ms=generation.latency_ms,
            prompt_tokens=generation.prompt_tokens,
            completion_tokens=generation.completion_tokens,
        )


def create_runtime_investigation_service(
    *,
    settings: Settings | None = None,
    cases_path: Path | None = None,
    rules_path: Path | None = None,
    sources_path: Path | None = None,
    top_k: int | None = None,
) -> InvestigationService:
    """Load checked-in configuration and local artifacts for CLI/runtime use."""

    runtime = settings or get_settings()
    root = runtime.project_root.resolve()
    resolved_cases = cases_path or root / "data" / "processed" / "incidents" / "cases.jsonl"
    resolved_rules = rules_path or root / "config" / "correlation_rules.yaml"
    resolved_sources = sources_path or root / "config" / "sources.yaml"
    detection_config = load_detection_config(
        resolved_rules,
        allowed_mitre_ids=configured_mitre_ids(resolved_sources),
    )
    llm = create_investigation_llm(
        provider=runtime.llm_provider,
        model=runtime.llm_model,
        api_key=runtime.resolved_llm_api_key,
        base_url=runtime.llm_base_url,
        timeout_seconds=runtime.llm_timeout_seconds,
        max_output_tokens=runtime.llm_max_output_tokens,
        thinking_level=runtime.gemini_thinking_level,
    )
    return InvestigationService(
        cases=load_investigation_cases(resolved_cases),
        detection_config=detection_config,
        retriever=get_dense_retriever(),
        llm=llm,
        top_k=top_k if top_k is not None else runtime.investigation_retrieval_top_k,
    )

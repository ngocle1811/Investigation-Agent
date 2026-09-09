"""Grounded investigation assembly, generation, validation, and demo evaluation tests."""

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from investigation_agent.detection.config import load_detection_config
from investigation_agent.detection.pipeline import process_incidents
from investigation_agent.evaluation.investigation import (
    evaluate_investigation_run,
    load_investigation_demo_cases,
    summarize_investigation_evaluations,
    validate_investigation_demo_cases,
)
from investigation_agent.events.scenario_templates import configured_mitre_ids
from investigation_agent.events.synthetic_generator import load_dataset
from investigation_agent.ingestion.schemas import KnowledgeChunk
from investigation_agent.ingestion.utils import sha256_text
from investigation_agent.investigation.assembler import InvestigationCaseAssembler
from investigation_agent.investigation.grounding import (
    GroundingValidationError,
    require_grounded_report,
    validate_report_grounding,
)
from investigation_agent.investigation.llm import (
    GeminiGenerateContentInvestigationLLM,
    MockInvestigationLLM,
    OpenAIResponsesInvestigationLLM,
    create_investigation_llm,
)
from investigation_agent.investigation.prompts import (
    INVESTIGATION_SYSTEM_PROMPT,
    build_investigation_prompt,
)
from investigation_agent.investigation.schemas import InvestigationReport, LLMGeneration
from investigation_agent.investigation.service import InvestigationService
from investigation_agent.rag.dense import (
    KnowledgeFilter,
    KnowledgeSearchResponse,
    RetrievalResult,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "config" / "correlation_rules.yaml"
SOURCES_PATH = PROJECT_ROOT / "config" / "sources.yaml"
DATASET_PATH = PROJECT_ROOT / "data" / "synthetic" / "incidents.jsonl"
DEMOS_PATH = PROJECT_ROOT / "data" / "golden" / "investigation_demo_cases.json"


@pytest.fixture(scope="module")
def detection_config():
    return load_detection_config(
        RULES_PATH,
        allowed_mitre_ids=configured_mitre_ids(SOURCES_PATH),
    )


@pytest.fixture(scope="module")
def cases(detection_config):
    result, _ = process_incidents(load_dataset(DATASET_PATH), detection_config)
    return result


def _knowledge_result(
    rank: int,
    chunk_id: str,
    title: str,
    *,
    technique_id: str | None = None,
) -> RetrievalResult:
    content = f"Security knowledge for {title}."
    chunk = KnowledgeChunk(
        chunk_id=chunk_id,
        document_id=f"doc-{chunk_id}",
        source="mitre_attack" if technique_id else "microsoft",
        source_type="mitre_attack" if technique_id else "sysmon_doc",
        title=title,
        section="Technique" if technique_id else "Event guidance",
        content=content,
        contextualized_content=f"Context: {content}",
        url="https://example.test/knowledge",
        version="test",
        technique_id=technique_id,
        content_hash=sha256_text(content),
    )
    return RetrievalResult.from_chunk(rank=rank, score=0.9 - (rank / 100), chunk=chunk)


class StaticKnowledgeRetriever:
    """Return behavior-relevant chunks without an embedding or Qdrant dependency."""

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: KnowledgeFilter | None = None,
    ) -> KnowledgeSearchResponse:
        results = [_knowledge_result(1, "chunk-general", "Sysmon event guidance")]
        if "T1110.001" in query:
            results.insert(
                0,
                _knowledge_result(
                    1,
                    "chunk-t1110-001",
                    "T1110.001 Password Guessing",
                    technique_id="T1110.001",
                ),
            )
        elif "T1059.001" in query:
            results.insert(
                0,
                _knowledge_result(
                    1,
                    "chunk-t1059-001",
                    "T1059.001 PowerShell",
                    technique_id="T1059.001",
                ),
            )
        results = [item.model_copy(update={"rank": rank}) for rank, item in enumerate(results, 1)]
        return KnowledgeSearchResponse(
            query=query,
            filters=filters or KnowledgeFilter(),
            results=results[:top_k],
        )

    def retrieve_parent(self, parent_id: str) -> KnowledgeChunk | None:
        return None


def _service(cases, detection_config, llm=None) -> InvestigationService:
    return InvestigationService(
        cases=cases,
        detection_config=detection_config,
        retriever=StaticKnowledgeRetriever(),
        llm=llm or MockInvestigationLLM(),
        top_k=5,
    )


def test_demo_fixtures_reference_three_real_detected_behaviors(cases, detection_config) -> None:
    demos = load_investigation_demo_cases(DEMOS_PATH)
    validate_investigation_demo_cases(demos, cases, detection_config)
    assert [demo.case_id for demo in demos] == [
        "INC-S02-V01",
        "INC-S04-V01",
        "INC-S08-V01",
    ]
    assert {demo.expected_behavior_type for demo in demos} == {
        "authentication_anomaly",
        "office_script_interpreter",
        "process_dns_network_activity",
    }


def test_assembler_uses_only_behavior_linked_evidence(cases, detection_config) -> None:
    demo = load_investigation_demo_cases(DEMOS_PATH)[0]
    case = next(item for item in cases if item.case_id == demo.case_id)
    evidence = InvestigationCaseAssembler(detection_config).assemble(
        case,
        behavior_id=demo.behavior_id,
    )
    assert {event.event_id for event in evidence.related_events} == set(demo.expected_key_event_ids)
    assert {match.rule_id for match in evidence.rule_matches} == set(demo.expected_rule_ids)
    assert "R001 Multiple Failed Logons" in evidence.retrieval_query
    assert "Windows Event ID 4625" in evidence.retrieval_query
    assert "T1110.001" in evidence.retrieval_query
    assert all("synthetic" not in event.details for event in evidence.related_events)
    assert "ground_truth" not in evidence.model_dump_json()


def test_prompt_has_separate_trusted_context_sections(cases, detection_config) -> None:
    run = _service(cases, detection_config).investigate_case("INC-S04-V01")
    prompt = build_investigation_prompt(run.context)
    assert "<CANDIDATE_BEHAVIOR>" in prompt
    assert "<INCIDENT_EVIDENCE>" in prompt
    assert "<SECURITY_KNOWLEDGE>" in prompt
    assert "ground_truth" not in prompt
    assert "Never invent" in INVESTIGATION_SYSTEM_PROMPT
    assert "does not prove" in run.report.limitations[1]
    assert "WS-75" in run.report.timeline[0].description


def test_grounding_accepts_known_references_and_rejects_unknown_ids(
    cases, detection_config
) -> None:
    run = _service(cases, detection_config).investigate_case("INC-S02-V01")
    assert validate_report_grounding(run.report, run.context).valid is True
    fabricated_timeline = run.report.timeline[0].model_copy(update={"event_id": "FABRICATED-EVENT"})
    fabricated_report = run.report.model_copy(
        update={"timeline": [fabricated_timeline, *run.report.timeline[1:]]}
    )
    validation = validate_report_grounding(fabricated_report, run.context)
    assert validation.valid is False
    assert validation.unknown_event_ids == ["FABRICATED-EVENT"]
    with pytest.raises(GroundingValidationError, match="FABRICATED-EVENT"):
        require_grounded_report(fabricated_report, run.context)

    wrong_time = run.report.timeline[0].model_copy(
        update={"timestamp": run.report.timeline[0].timestamp + timedelta(seconds=1)}
    )
    wrong_time_report = run.report.model_copy(
        update={"timeline": [wrong_time, *run.report.timeline[1:]]}
    )
    assert (
        validate_report_grounding(wrong_time_report, run.context).timeline_timestamps_match_evidence
        is False
    )

    finding = run.report.findings[0].model_copy(
        update={"knowledge_chunk_ids": ["fabricated-chunk"]}
    )
    fabricated_knowledge = run.report.model_copy(
        update={"findings": [finding, *run.report.findings[1:]]}
    )
    validation = validate_report_grounding(fabricated_knowledge, run.context)
    assert validation.all_knowledge_refs_exist is False
    assert validation.unknown_knowledge_chunk_ids == ["fabricated-chunk"]

    mentioned_report = run.report.model_copy(
        update={"summary": run.report.summary + " INC-S99-V99-E9999"}
    )
    assert validate_report_grounding(mentioned_report, run.context).unknown_event_ids == [
        "INC-S99-V99-E9999"
    ]


def test_mitre_mapping_requires_matching_retrieved_knowledge(cases, detection_config) -> None:
    run = _service(cases, detection_config).investigate_case("INC-S04-V01")
    assert [item.technique_id for item in run.report.mitre_techniques] == ["T1059.001"]
    unsupported = run.report.mitre_techniques[0].model_copy(update={"technique_id": "T9999"})
    report = run.report.model_copy(update={"mitre_techniques": [unsupported]})
    validation = validate_report_grounding(report, run.context)
    assert validation.mitre_knowledge_support_valid is False
    assert validation.unsupported_mitre_techniques == ["T9999"]


def test_all_three_demo_cases_run_end_to_end_and_pass_checks(cases, detection_config) -> None:
    demos = load_investigation_demo_cases(DEMOS_PATH)
    service = _service(cases, detection_config)
    runs = [service.investigate_case(demo.case_id, behavior_id=demo.behavior_id) for demo in demos]
    evaluations = [
        evaluate_investigation_run(run, demo) for run, demo in zip(runs, demos, strict=True)
    ]
    summary = summarize_investigation_evaluations(evaluations)
    assert summary.total_cases == 3
    assert summary.passed_cases == 3
    assert summary.failed_cases == 0
    assert all(run.grounding.valid for run in runs)
    assert all(run.report.recommended_actions for run in runs)


class HallucinatingLLM:
    provider = "test"
    model = "hallucinating-test-model"

    def generate(self, *, system_prompt: str, user_prompt: str, context) -> LLMGeneration:
        valid = MockInvestigationLLM().generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context=context,
        )
        timeline = valid.report.timeline[0].model_copy(update={"event_id": "INC-S04-V01-E9999"})
        report = valid.report.model_copy(update={"timeline": [timeline]})
        return valid.model_copy(
            update={"report": report, "provider": self.provider, "model": self.model}
        )


def test_service_fails_closed_on_hallucinated_event_reference(cases, detection_config) -> None:
    service = _service(cases, detection_config, HallucinatingLLM())
    with pytest.raises(GroundingValidationError, match="INC-S04-V01-E9999"):
        service.investigate_case("INC-S04-V01")


def test_service_rejects_missing_case_or_behavior(cases, detection_config) -> None:
    service = _service(cases, detection_config)
    with pytest.raises(ValueError, match="case not found"):
        service.investigate_case("INC-S99-V99")
    with pytest.raises(ValueError, match="candidate behavior"):
        service.investigate_case("INC-S02-V01", behavior_id="missing")


def test_llm_provider_factory_and_sdk_generation(cases, detection_config, monkeypatch) -> None:
    assert isinstance(create_investigation_llm(provider="mock", model="mock"), MockInvestigationLLM)
    with pytest.raises(ValueError, match="LLM_API_KEY"):
        create_investigation_llm(provider="openai", model="test")
    openai_payload = {
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": '{"case_id":"example"}'}],
            }
        ]
    }
    assert OpenAIResponsesInvestigationLLM._output_text(openai_payload) == '{"case_id":"example"}'

    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        create_investigation_llm(provider="gemini", model="gemini-test")
    gemini = create_investigation_llm(
        provider="gemini",
        model="gemini-test",
        api_key=SecretStr("test-key"),
        thinking_level="low",
    )
    assert isinstance(gemini, GeminiGenerateContentInvestigationLLM)
    mock_run = _service(cases, detection_config).investigate_case("INC-S02-V01")
    captured = {}

    class FakeGeminiClient:
        def __init__(self, **kwargs) -> None:
            captured["client_kwargs"] = kwargs
            self.models = self

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def generate_content(self, **kwargs):
            captured["generate_kwargs"] = kwargs
            return SimpleNamespace(
                parsed=mock_run.report,
                text=mock_run.report.model_dump_json(),
                prompt_feedback=None,
                usage_metadata=SimpleNamespace(
                    prompt_token_count=123,
                    candidates_token_count=45,
                ),
            )

    monkeypatch.setattr("investigation_agent.investigation.llm.genai.Client", FakeGeminiClient)
    generation = gemini.generate(
        system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        user_prompt=build_investigation_prompt(mock_run.context),
        context=mock_run.context,
    )
    assert generation.report == mock_run.report
    assert generation.prompt_tokens == 123
    assert generation.completion_tokens == 45
    assert captured["generate_kwargs"]["model"] == "gemini-test"
    retry_options = captured["client_kwargs"]["http_options"].retry_options
    assert retry_options.attempts == 5
    assert retry_options.http_status_codes == [429, 500, 502, 503, 504]
    response_schema = captured["generate_kwargs"]["config"].response_json_schema
    assert response_schema["title"] == InvestigationReport.__name__
    assert response_schema["additionalProperties"] is False
    assert "minLength" not in str(response_schema)
    assert captured["generate_kwargs"]["config"].thinking_config.thinking_level.value == "LOW"

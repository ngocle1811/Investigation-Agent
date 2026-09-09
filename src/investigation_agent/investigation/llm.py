"""Provider abstraction plus mock, OpenAI, and Gemini structured-output adapters."""

from __future__ import annotations

from time import perf_counter
from typing import Protocol, runtime_checkable

import httpx
from google import genai
from google.genai import types
from pydantic import SecretStr

from investigation_agent.investigation.schemas import (
    ClaimType,
    Confidence,
    Finding,
    InvestigationContext,
    InvestigationReport,
    LLMGeneration,
    MitreTechnique,
    Priority,
    RecommendedAction,
    SuspiciousReason,
    TimelineItem,
)

_TECHNIQUE_NAMES = {
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1110.001": "Brute Force: Password Guessing",
}

_ACTIONS = {
    "authentication_anomaly": [
        (
            "Verify the account activity with the user and identity owner.",
            "Confirm whether the observed authentication sequence was expected.",
        ),
        (
            "Review authentication history for the source IP and account.",
            "Identify preceding failures and any follow-on access using the same identity.",
        ),
    ],
    "office_script_interpreter": [
        (
            "Review the Office document and complete process tree.",
            "Determine what caused the Office process to launch the script interpreter.",
        ),
        (
            "Validate the PowerShell command with the user and endpoint owner.",
            "Establish whether the command was authorized and expected.",
        ),
    ],
    "powershell_network_activity": [
        (
            "Review the complete PowerShell process tree and command history.",
            "Identify the initiating process and validate the observed command context.",
        ),
        (
            "Investigate the resolved domain and external destination.",
            "Determine whether the network activity was approved for this process.",
        ),
    ],
    "process_dns_network_activity": [
        (
            "Investigate the resolved domain and destination IP.",
            "Determine reputation, ownership, and whether the destination is expected.",
        ),
        (
            "Review the originating process tree and script source.",
            "Establish why the process performed the DNS lookup and connection.",
        ),
    ],
    "scheduled_task_persistence": [
        (
            "Inspect the scheduled task definition and creator context.",
            "Validate the trigger, action, author, and creation origin.",
        ),
        (
            "Review process activity launched by the task.",
            "Determine whether task execution produced unexpected child activity.",
        ),
    ],
}


@runtime_checkable
class StructuredInvestigationLLM(Protocol):
    """Replaceable provider contract for strict investigation generation."""

    provider: str
    model: str

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context: InvestigationContext,
    ) -> LLMGeneration:
        """Return a schema-validated report and provider metadata."""


def _event_description(event) -> str:
    fields = [event.event_type.replace("_", " ")]
    if event.source_event_id:
        fields.append(f"source event {event.source_event_id}")
    if event.host:
        fields.append(f"on {event.host}")
    if event.user:
        fields.append(f"for {event.user}")
    if event.process_name:
        fields.append(f"process {event.process_name}")
    if event.parent_process_name:
        fields.append(f"parent {event.parent_process_name}")
    if event.src_ip:
        fields.append(f"source {event.src_ip}")
    if event.dst_domain:
        fields.append(f"domain {event.dst_domain}")
    if event.dst_ip:
        destination = f"destination {event.dst_ip}"
        if event.dst_port:
            destination += f":{event.dst_port}"
        fields.append(destination)
    description = "; ".join(fields)
    return description[0].upper() + description[1:] + "."


def _chunk_supports(technique_id: str, item) -> bool:
    if item.technique_id == technique_id:
        return True
    return any(
        str(tag).casefold() == f"attack.{technique_id}".casefold()
        for tag in item.metadata.get("tags", [])
    )


class MockInvestigationLLM:
    """Deterministic offline investigator for demos and stable tests, not a detector."""

    provider = "mock"

    def __init__(self, model: str = "mock-investigator-v1") -> None:
        self.model = model

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context: InvestigationContext,
    ) -> LLMGeneration:
        """Construct a grounded representative report only from supplied structured context."""

        del system_prompt, user_prompt
        started = perf_counter()
        event_ids = [event.event_id for event in context.related_events]
        knowledge_ids = [item.chunk_id for item in context.retrieved_knowledge[:2]]
        techniques: list[MitreTechnique] = []
        missing_techniques: list[str] = []
        configured_techniques = list(
            dict.fromkeys(
                technique for rule in context.rule_context for technique in rule.mitre_techniques
            )
        )
        for technique_id in configured_techniques:
            supporting_chunks = [
                item.chunk_id
                for item in context.retrieved_knowledge
                if _chunk_supports(technique_id, item)
            ]
            if not supporting_chunks:
                missing_techniques.append(technique_id)
                continue
            techniques.append(
                MitreTechnique(
                    technique_id=technique_id,
                    name=_TECHNIQUE_NAMES.get(technique_id, technique_id),
                    reason=(
                        "The deterministic rules map this observed behavior to the technique, "
                        "and the cited security knowledge supports that mapping."
                    ),
                    evidence_event_ids=event_ids,
                    knowledge_chunk_ids=supporting_chunks[:2],
                )
            )
        actions = _ACTIONS.get(
            context.candidate_behavior.behavior_type,
            [
                (
                    "Review the supporting event sequence and affected entities.",
                    "Validate the deterministic detection in its operational context.",
                )
            ],
        )
        limitations = [
            "The analysis is bounded to events linked by deterministic detection.",
            (
                "This report identifies investigation leads and does not prove that compromise "
                "occurred."
            ),
        ]
        if missing_techniques:
            limitations.append(
                "No retrieved knowledge chunk directly supported configured technique(s): "
                + ", ".join(missing_techniques)
                + "."
            )
        report = InvestigationReport(
            case_id=context.case_id,
            summary=(
                f"Deterministic detection correlated {len(event_ids)} events as "
                f"{context.candidate_behavior.behavior_type.replace('_', ' ')}; analyst "
                "validation is required before drawing a compromise conclusion."
            ),
            summary_evidence_event_ids=event_ids,
            timeline=[
                TimelineItem(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    description=_event_description(event),
                )
                for event in context.related_events
            ],
            findings=[
                Finding(
                    title="Deterministically correlated behavior",
                    explanation=context.candidate_behavior.description,
                    claim_type=ClaimType.FACT,
                    evidence_event_ids=event_ids,
                    knowledge_chunk_ids=[],
                    confidence=Confidence.HIGH,
                ),
                Finding(
                    title="Security interpretation requires analyst validation",
                    explanation=(
                        "The sequence resembles behavior described by the retrieved security "
                        "knowledge, but intent and authorization are not established by telemetry."
                    ),
                    claim_type=ClaimType.INFERENCE,
                    evidence_event_ids=event_ids,
                    knowledge_chunk_ids=knowledge_ids,
                    confidence=Confidence.MEDIUM,
                ),
            ],
            why_suspicious=[
                SuspiciousReason(
                    reason=match.reason,
                    evidence_event_ids=match.matched_event_ids,
                    knowledge_chunk_ids=[],
                )
                for match in context.rule_matches
            ],
            mitre_techniques=techniques,
            recommended_actions=[
                RecommendedAction(action=action, reason=reason, priority=Priority.HIGH)
                for action, reason in actions
            ],
            limitations=limitations,
        )
        latency_ms = round((perf_counter() - started) * 1000, 3)
        return LLMGeneration(
            report=report,
            provider=self.provider,
            model=self.model,
            latency_ms=latency_ms,
        )


class OpenAIResponsesInvestigationLLM:
    """OpenAI Responses API adapter using strict JSON-schema structured output."""

    provider = "openai"

    def __init__(
        self,
        *,
        model: str,
        api_key: SecretStr,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 60.0,
        max_output_tokens: int = 3000,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens

    @staticmethod
    def _output_text(payload: dict) -> str:
        for item in payload.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    return content["text"]
        raise ValueError("OpenAI response did not contain structured output text")

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context: InvestigationContext,
    ) -> LLMGeneration:
        """Request strict structured output; grounding is still validated by the service."""

        del context
        started = perf_counter()
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(
                f"{self.base_url}/responses",
                headers={
                    "Authorization": f"Bearer {self.api_key.get_secret_value()}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "instructions": system_prompt,
                    "input": user_prompt,
                    "max_output_tokens": self.max_output_tokens,
                    "store": False,
                    "text": {
                        "format": {
                            "type": "json_schema",
                            "name": "investigation_report",
                            "strict": True,
                            "schema": InvestigationReport.model_json_schema(),
                        }
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
        report = InvestigationReport.model_validate_json(self._output_text(payload))
        usage = payload.get("usage") or {}
        return LLMGeneration(
            report=report,
            provider=self.provider,
            model=self.model,
            latency_ms=round((perf_counter() - started) * 1000, 3),
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
        )


_GEMINI_JSON_SCHEMA_FIELDS = frozenset(
    {
        "$id",
        "$ref",
        "$anchor",
        "type",
        "format",
        "title",
        "description",
        "enum",
        "items",
        "prefixItems",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "anyOf",
        "oneOf",
        "properties",
        "additionalProperties",
        "required",
        "$defs",
    }
)


def _gemini_json_schema(value):
    """Keep the standard JSON Schema subset accepted by Gemini structured output."""

    if isinstance(value, list):
        return [_gemini_json_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key not in _GEMINI_JSON_SCHEMA_FIELDS:
            continue
        if key in {"$defs", "properties"} and isinstance(item, dict):
            result[key] = {name: _gemini_json_schema(schema) for name, schema in item.items()}
        else:
            result[key] = _gemini_json_schema(item)
    return result


class GeminiGenerateContentInvestigationLLM:
    """Official Google Gen AI SDK adapter using Pydantic structured output."""

    provider = "gemini"
    official_base_url = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(
        self,
        *,
        model: str,
        api_key: SecretStr,
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_output_tokens: int = 3000,
        thinking_level: str | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key
        configured_base_url = (base_url or self.official_base_url).rstrip("/")
        if configured_base_url != self.official_base_url:
            raise ValueError(
                "Custom LLM_BASE_URL is not supported by the Gemini Developer API SDK adapter"
            )
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens
        self.thinking_level = thinking_level or None

    @staticmethod
    def _report_from_response(response) -> InvestigationReport:
        parsed = response.parsed
        if isinstance(parsed, InvestigationReport):
            return parsed
        if parsed is not None:
            return InvestigationReport.model_validate(parsed)
        if response.text:
            return InvestigationReport.model_validate_json(response.text)
        feedback = response.prompt_feedback
        block_reason = getattr(feedback, "block_reason", None)
        suffix = f" (prompt blocked: {block_reason})" if block_reason else ""
        raise ValueError(f"Gemini response did not contain structured output{suffix}")

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context: InvestigationContext,
    ) -> LLMGeneration:
        """Request JSON output; grounding is still validated by the service."""

        del context
        started = perf_counter()
        secret = self.api_key.get_secret_value()
        try:
            with genai.Client(
                api_key=secret,
                http_options=types.HttpOptions(
                    api_version="v1beta",
                    timeout=round(self.timeout_seconds * 1000),
                    retry_options=types.HttpRetryOptions(
                        attempts=5,
                        initial_delay=2,
                        max_delay=20,
                        exp_base=2,
                        jitter=1,
                        http_status_codes=[429, 500, 502, 503, 504],
                    ),
                ),
            ) as client:
                response = client.models.generate_content(
                    model=self.model,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        response_mime_type="application/json",
                        response_json_schema=_gemini_json_schema(
                            InvestigationReport.model_json_schema()
                        ),
                        max_output_tokens=self.max_output_tokens,
                        thinking_config=(
                            types.ThinkingConfig(thinking_level=self.thinking_level)
                            if self.thinking_level
                            else None
                        ),
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(
                            disable=True
                        ),
                    ),
                )
        except Exception as exc:
            safe_message = str(exc).replace(secret, "<redacted>")
            raise RuntimeError(
                f"Gemini generation failed for configured model {self.model}: "
                f"{type(exc).__name__}: {safe_message}"
            ) from None
        report = self._report_from_response(response)
        usage = response.usage_metadata
        return LLMGeneration(
            report=report,
            provider=self.provider,
            model=self.model,
            latency_ms=round((perf_counter() - started) * 1000, 3),
            prompt_tokens=getattr(usage, "prompt_token_count", None),
            completion_tokens=getattr(usage, "candidates_token_count", None),
        )


def create_investigation_llm(
    *,
    provider: str,
    model: str,
    api_key: SecretStr | None = None,
    base_url: str | None = None,
    timeout_seconds: float = 60.0,
    max_output_tokens: int = 3000,
    thinking_level: str | None = None,
) -> StructuredInvestigationLLM:
    """Create a provider without coupling orchestration to one vendor."""

    normalized = provider.casefold()
    if normalized == "mock":
        return MockInvestigationLLM(model)
    if normalized == "openai":
        if api_key is None or not api_key.get_secret_value().strip():
            raise ValueError("LLM_API_KEY is required when LLM_PROVIDER=openai")
        return OpenAIResponsesInvestigationLLM(
            model=model,
            api_key=api_key,
            base_url=base_url or "https://api.openai.com/v1",
            timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens,
        )
    if normalized == "gemini":
        if api_key is None or not api_key.get_secret_value().strip():
            raise ValueError("GEMINI_API_KEY or LLM_API_KEY is required when LLM_PROVIDER=gemini")
        return GeminiGenerateContentInvestigationLLM(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens,
            thinking_level=thinking_level,
        )
    raise ValueError(f"Unsupported investigation LLM provider: {provider}")

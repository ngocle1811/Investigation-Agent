# Investigation Agent: two-minute demo

This prototype does not ask an LLM to detect attacks in raw logs. Deterministic rules first find a
candidate behavior; the LLM receives only the linked evidence and retrieved public security
knowledge. A deterministic validator rejects unknown evidence or unsupported MITRE references.

The example below is the live Gemini result for synthetic case `INC-S04-V01`.

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
deterministic rules R003 + R004 + R010
    ↓
CandidateBehavior: office_script_interpreter
    ↓
incident evidence + Qdrant-retrieved security knowledge
    ↓
Gemini investigation
    ↓
grounding validator
    ↓
structured InvestigationReport
```

## What the report says

Summary: on `WS-75`, Microsoft Word spawned PowerShell for `user04`. This is an observed
parent-child process relationship, not proof that the host is compromised.

Key timeline:

1. `2026-01-18T08:00:59Z` — `WINWORD.EXE` PID 7063 was launched by `explorer.exe`.
   Evidence: `INC-S04-V01-E0039`.
2. `2026-01-18T08:01:34Z` — Word PID 7063 spawned `powershell.exe` PID 51221 with an inline
   `-Command` argument. Evidence: `INC-S04-V01-E0044`.

The report maps the behavior to MITRE ATT&CK `T1059.001` (PowerShell), citing event
`INC-S04-V01-E0044` and retrieved chunk `chk-1440cde9af406d56f166da59983559ae`.

Recommended analyst actions:

- Inspect the document for macros, scripts, or external templates.
- Review the PowerShell process tree and script-block logs.
- Check contemporaneous host and network telemetry for follow-on activity.

Limitations are explicit: the synthetic command content is masked, and the bounded case lacks the
network and file telemetry required to determine what happened after PowerShell started.

## Grounding failure is fail-closed

The deterministic negative test changes a timeline reference to the fabricated event
`INC-S04-V01-E9999`:

```text
InvestigationReport
    ↓
grounding validator
    ↓
GroundingValidationError: unknown event INC-S04-V01-E9999
```

The test does not call Gemini. It demonstrates that schema-valid model output is still rejected
when its evidence references are not in the supplied investigation context.

## Reproduce

With Qdrant populated and `GEMINI_API_KEY` configured in the gitignored `.env`:

```powershell
python scripts/investigate_case.py `
  --case-id INC-S04-V01 `
  --behavior-id BH-INC-S04-V01-office_script_interpreter-6e2c6df3aa2a `
  --llm-provider gemini `
  --output artifacts/eval/gemini_INC-S04-V01.json
```

Run all three locked demonstrations and their deterministic evaluation:

```powershell
python scripts/investigate_case.py --demo-all --llm-provider gemini `
  --output artifacts/eval/investigation_demo_gemini.json
```

The live artifact contains the bounded investigation case, retrieval query, retrieved chunk IDs,
structured report, grounding result, model/token/latency metadata, and evaluation booleans. It does
not contain the API key or raw provider response metadata.

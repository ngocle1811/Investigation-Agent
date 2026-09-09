"""Dedicated grounded SOC investigation prompt construction."""

import json

from investigation_agent.investigation.schemas import InvestigationContext

INVESTIGATION_SYSTEM_PROMPT = """You are a SOC investigation assistant.

Detection has already been performed by deterministic rules and correlation. Do not decide
whether raw events should have triggered detection. Investigate only the supplied
CandidateBehavior.

Grounding rules:
- Use INCIDENT_EVIDENCE only for statements about what happened in this incident.
- Use SECURITY_KNOWLEDGE only for general interpretation and MITRE ATT&CK mapping.
- Never invent an event, timestamp, IP, host, user, process, command, rule, or citation.
- Every incident-specific summary, timeline item, finding, suspicious reason, and MITRE mapping
  must cite one or more supplied event IDs.
- Cite only supplied knowledge chunk IDs. Map a MITRE technique only when a cited retrieved chunk
  supports that technique; otherwise omit the mapping and state the limitation.
- Mark direct observations as fact and analytical interpretation as inference.
- If evidence is insufficient, explicitly state the limitation.
- Recommended actions are investigation steps, not claims that compromise definitely occurred.

Return only the requested structured InvestigationReport."""


def build_investigation_prompt(context: InvestigationContext) -> str:
    """Serialize three visibly separated, bounded context blocks for structured generation."""

    behavior = context.candidate_behavior.model_dump(mode="json")
    evidence = {
        "case_id": context.case_id,
        "rule_matches": [match.model_dump(mode="json") for match in context.rule_matches],
        "rule_context": [rule.model_dump(mode="json") for rule in context.rule_context],
        "related_events": [event.model_dump(mode="json") for event in context.related_events],
    }
    knowledge = [item.model_dump(mode="json") for item in context.retrieved_knowledge]
    return "\n".join(
        [
            "<CANDIDATE_BEHAVIOR>",
            json.dumps(behavior, ensure_ascii=False, indent=2),
            "</CANDIDATE_BEHAVIOR>",
            "<INCIDENT_EVIDENCE>",
            json.dumps(evidence, ensure_ascii=False, indent=2),
            "</INCIDENT_EVIDENCE>",
            "<SECURITY_KNOWLEDGE>",
            json.dumps(knowledge, ensure_ascii=False, indent=2),
            "</SECURITY_KNOWLEDGE>",
        ]
    )

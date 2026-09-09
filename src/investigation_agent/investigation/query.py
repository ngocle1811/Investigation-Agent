"""Deterministic knowledge-query construction from trusted detection output."""

from collections.abc import Sequence

from investigation_agent.detection.schemas import CandidateBehavior, DetectionRule, RuleMatch
from investigation_agent.events.schemas import SecurityEvent, SourceType

_BEHAVIOR_CONCEPTS = {
    "authentication_anomaly": "account compromise brute force password guessing valid accounts",
    "powershell_network_activity": (
        "PowerShell execution DNS external network command and control investigation"
    ),
    "office_script_interpreter": (
        "Office parent process script interpreter PowerShell suspicious process tree"
    ),
    "external_login_process_activity": (
        "external successful authentication followed by process and network activity"
    ),
    "scheduled_task_persistence": "scheduled task creation execution persistence",
    "process_dns_network_activity": (
        "process DNS resolution followed by external network connection command and control"
    ),
    "powershell_execution": "PowerShell process creation command and script execution",
    "process_network_activity": "process followed by external network connection",
    "suspicious_command_marker": "suspicious PowerShell command execution",
}


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def build_retrieval_query(
    behavior: CandidateBehavior,
    matches: Sequence[RuleMatch],
    events: Sequence[SecurityEvent],
    rules: dict[str, DetectionRule],
) -> str:
    """Build one focused query without asking an LLM to reinterpret raw case logs."""

    ordered_rule_ids = _unique([match.rule_id for match in matches])
    detections = [
        f"{rule_id} {rules[rule_id].name}: {rules[rule_id].description}"
        for rule_id in ordered_rule_ids
    ]
    telemetry: list[str] = []
    for event in events:
        if event.source_type == SourceType.WINDOWS_SECURITY and event.source_event_id:
            telemetry.append(f"Windows Event ID {event.source_event_id} {event.event_type.value}")
        elif event.source_type == SourceType.SYSMON and event.source_event_id:
            telemetry.append(f"Sysmon Event ID {event.source_event_id} {event.event_type.value}")
        else:
            telemetry.append(f"{event.source_type.value} {event.event_type.value}")
    techniques = _unique(
        [technique for rule_id in ordered_rule_ids for technique in rules[rule_id].mitre_techniques]
    )
    concepts = _BEHAVIOR_CONCEPTS.get(
        behavior.behavior_type,
        behavior.behavior_type.replace("_", " "),
    )
    sections = [
        f"Behavior {behavior.behavior_type}: {behavior.description}",
        f"Detections: {'; '.join(detections)}",
        f"Telemetry: {'; '.join(_unique(telemetry))}",
        f"Security concepts: {concepts}",
    ]
    if techniques:
        sections.append(f"MITRE ATT&CK techniques: {' '.join(techniques)}")
    return ". ".join(section.rstrip(". ") for section in sections) + "."

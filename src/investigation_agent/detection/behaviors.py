"""Deterministic aggregation of related rule matches into candidate behaviors."""

import hashlib
from collections.abc import Iterable

from investigation_agent.detection.rules import entities_from_events
from investigation_agent.detection.schemas import (
    CandidateBehavior,
    DetectionConfig,
    RuleMatch,
    Severity,
)
from investigation_agent.events.schemas import SecurityEvent

_BEHAVIOR_DESCRIPTIONS = {
    "authentication_anomaly": (
        "Repeated authentication failures, optionally followed by success, share one identity."
    ),
    "powershell_network_activity": (
        "PowerShell and correlated DNS or external network activity share one process context."
    ),
    "office_script_interpreter": (
        "An Office process created a script interpreter with supporting command context."
    ),
    "external_login_process_activity": (
        "An external successful login was followed by same-user process activity."
    ),
    "scheduled_task_persistence": (
        "Scheduled-task creation and later execution form a persistence candidate."
    ),
    "process_dns_network_activity": (
        "A process performed DNS resolution and then connected to the external destination."
    ),
    "powershell_execution": (
        "PowerShell execution is retained as a low-level candidate requiring context review."
    ),
    "process_network_activity": (
        "A process and external network connection share a host and process identifier."
    ),
    "suspicious_command_marker": (
        "A configured exact synthetic command marker was observed in process telemetry."
    ),
}


def severity_label_for_score(config: DetectionConfig, score: int) -> str:
    """Map a deterministic score to the highest configured severity threshold."""

    label = "none"
    for severity in Severity:
        if score >= config.case_scoring.label_thresholds[severity]:
            label = severity.value
    return label


def _make_behavior(
    behavior_type: str,
    case_id: str,
    matches: list[RuleMatch],
    events_by_id: dict[str, SecurityEvent],
    config: DetectionConfig,
) -> CandidateBehavior:
    stable_matches = sorted(matches, key=lambda match: match.match_id)
    event_ids = sorted(
        {event_id for match in stable_matches for event_id in match.matched_event_ids},
        key=lambda event_id: (
            events_by_id[event_id].timestamp,
            event_id,
        ),
    )
    evidence = [events_by_id[event_id] for event_id in event_ids]
    rule_ids = {match.rule_id for match in stable_matches}
    score = sum(config.severity_weights[config.rules[rule_id].severity] for rule_id in rule_ids)
    digest = hashlib.sha256(
        "\x1f".join(match.match_id for match in stable_matches).encode("utf-8")
    ).hexdigest()[:12]
    return CandidateBehavior(
        behavior_id=f"BH-{case_id}-{behavior_type}-{digest}",
        behavior_type=behavior_type,
        case_id=case_id,
        supporting_rule_match_ids=[match.match_id for match in stable_matches],
        supporting_event_ids=event_ids,
        start_time=min(event.timestamp for event in evidence),
        end_time=max(event.timestamp for event in evidence),
        entities=entities_from_events(evidence),
        severity=Severity(severity_label_for_score(config, score)),
        deterministic_score=score,
        description=_BEHAVIOR_DESCRIPTIONS[behavior_type],
    )


def aggregate_behaviors(
    case_id: str,
    rule_matches: Iterable[RuleMatch],
    events: Iterable[SecurityEvent],
    config: DetectionConfig,
) -> list[CandidateBehavior]:
    """Collapse overlapping rules into a small set of traceable candidate behaviors."""

    matches = list(rule_matches)
    events_by_id = {event.event_id: event for event in events}
    available = {match.match_id: match for match in matches}
    behaviors: list[CandidateBehavior] = []

    def take(behavior_type: str, rule_ids: set[str], *, require: str | None = None) -> bool:
        selected = [match for match in available.values() if match.rule_id in rule_ids]
        if not selected or (require and not any(match.rule_id == require for match in selected)):
            return False
        behaviors.append(_make_behavior(behavior_type, case_id, selected, events_by_id, config))
        for match in selected:
            available.pop(match.match_id)
        return True

    take("authentication_anomaly", {"R001", "R002"})
    if not take(
        "powershell_network_activity",
        {"R003", "R005", "R006", "R009", "R010"},
        require="R006",
    ):
        take(
            "office_script_interpreter",
            {"R003", "R004", "R010"},
            require="R004",
        )
    take(
        "external_login_process_activity",
        {"R005", "R007"},
        require="R007",
    )
    take("scheduled_task_persistence", {"R008"}, require="R008")
    take(
        "process_dns_network_activity",
        {"R005", "R009"},
        require="R009",
    )
    take("powershell_execution", {"R003", "R010"}, require="R003")
    take("process_network_activity", {"R005"}, require="R005")
    take("suspicious_command_marker", {"R010"}, require="R010")

    if available:
        unknown = sorted({match.rule_id for match in available.values()})
        raise ValueError(f"No behavior aggregation mapping for rule matches: {unknown}")
    return sorted(
        behaviors,
        key=lambda behavior: (
            behavior.start_time,
            behavior.end_time,
            behavior.behavior_type,
        ),
    )

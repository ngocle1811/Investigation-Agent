"""Deterministic rule evaluation over normalized security events."""

import hashlib
import ipaddress
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from investigation_agent.detection.correlation import (
    deduplicate_events,
    find_followed_by,
    group_by_entity,
    match_parent_child,
    match_same_process,
    normalize_process_name,
    sort_events_by_timestamp,
)
from investigation_agent.detection.schemas import (
    DetectionConfig,
    DetectionRule,
    EntitySet,
    RuleMatch,
)
from investigation_agent.events.schemas import EventType, SecurityEvent


def entities_from_events(events: Iterable[SecurityEvent]) -> EntitySet:
    """Extract stable entity lists without consulting synthetic ground truth."""

    event_list = list(events)
    return EntitySet(
        hosts=[event.host for event in event_list if event.host],
        users=[event.user for event in event_list if event.user],
        ips=[value for event in event_list for value in (event.src_ip, event.dst_ip) if value],
        processes=[event.process_name for event in event_list if event.process_name],
        domains=[event.dst_domain for event in event_list if event.dst_domain],
    )


def _parameter_int(rule: DetectionRule, name: str) -> int:
    value = rule.parameters.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{rule.rule_id}.{name} must be a positive integer")
    return value


def _parameter_strings(rule: DetectionRule, name: str) -> list[str]:
    value = rule.parameters.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{rule.rule_id}.{name} must be a list of strings")
    return value


def _casefold_set(rule: DetectionRule, name: str) -> set[str]:
    return {item.casefold() for item in _parameter_strings(rule, name)}


def _is_external_ip(value: str | None, internal_cidrs: list[str]) -> bool:
    if not value:
        return False
    address = ipaddress.ip_address(value)
    return not any(address in ipaddress.ip_network(cidr) for cidr in internal_cidrs)


def _trusted_context(
    process: SecurityEvent,
    related_events: Iterable[SecurityEvent],
    rule: DetectionRule,
) -> bool:
    trusted_processes = _casefold_set(rule, "trusted_process_names")
    trusted_parents = _casefold_set(rule, "trusted_parent_process_names")
    trusted_markers = _casefold_set(rule, "trusted_command_markers")
    trusted_domain_prefixes = _casefold_set(rule, "trusted_domain_prefixes")
    if normalize_process_name(process.process_name) in trusted_processes:
        return True
    if normalize_process_name(process.parent_process_name) in trusted_parents:
        return True
    command_line = (process.command_line or "").casefold()
    if any(marker in command_line for marker in trusted_markers):
        return True
    return any(
        event.dst_domain
        and any(
            event.dst_domain.casefold().startswith(prefix) for prefix in trusted_domain_prefixes
        )
        for event in related_events
    )


def _make_match(
    rule: DetectionRule,
    case_id: str,
    events: Iterable[SecurityEvent],
    *,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> RuleMatch:
    evidence = deduplicate_events(events)
    event_ids = [event.event_id for event in evidence]
    digest = hashlib.sha256("\x1f".join(event_ids).encode("utf-8")).hexdigest()[:12]
    return RuleMatch(
        match_id=f"RM-{case_id}-{rule.rule_id}-{digest}",
        rule_id=rule.rule_id,
        case_id=case_id,
        matched_event_ids=event_ids,
        start_time=evidence[0].timestamp,
        end_time=evidence[-1].timestamp,
        entities=entities_from_events(evidence),
        severity=rule.severity,
        reason=reason,
        metadata=metadata or {},
    )


def _non_overlapping_threshold_windows(
    events: list[SecurityEvent], threshold: int, window_seconds: int
) -> list[list[SecurityEvent]]:
    """Return stable threshold windows without emitting overlapping duplicate matches."""

    ordered = sort_events_by_timestamp(events)
    matches: list[list[SecurityEvent]] = []
    start = 0
    while start <= len(ordered) - threshold:
        window = [
            event
            for event in ordered[start:]
            if (event.timestamp - ordered[start].timestamp).total_seconds() <= window_seconds
        ]
        if len(window) >= threshold:
            matches.append(window)
            start += len(window)
        else:
            start += 1
    return matches


class DetectionEngine:
    """Evaluate configured rules against canonicalized, deduplicated events."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._evaluators: dict[
            str, Callable[[DetectionRule, str, list[SecurityEvent]], list[RuleMatch]]
        ] = {
            "R001": self._r001_multiple_failed_logons,
            "R002": self._r002_failed_then_success,
            "R003": self._r003_powershell_execution,
            "R004": self._r004_office_to_interpreter,
            "R005": self._r005_process_to_network,
            "R006": self._r006_powershell_to_network,
            "R007": self._r007_external_login_to_process,
            "R008": self._r008_scheduled_task_chain,
            "R009": self._r009_dns_to_network,
            "R010": self._r010_command_marker,
        }

    def evaluate(
        self, case_id: str, events: Iterable[SecurityEvent]
    ) -> tuple[list[SecurityEvent], list[RuleMatch]]:
        """Return the canonical evidence view and stable rule matches."""

        canonical = deduplicate_events(events)
        matches: list[RuleMatch] = []
        for rule_id, rule in self.config.rules.items():
            if not rule.enabled:
                continue
            evaluator = self._evaluators.get(rule_id)
            if evaluator is None:
                raise ValueError(f"No evaluator is implemented for enabled rule {rule_id}")
            matches.extend(evaluator(rule, case_id, canonical))
        by_id = {match.match_id: match for match in matches}
        stable = sorted(
            by_id.values(),
            key=lambda match: (match.start_time, match.end_time, match.rule_id, match.match_id),
        )
        return canonical, stable

    def _r001_multiple_failed_logons(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        threshold = _parameter_int(rule, "failed_login_threshold")
        window_seconds = _parameter_int(rule, "window_seconds")
        failures = [event for event in events if event.event_type == EventType.FAILED_LOGON]
        matches: list[RuleMatch] = []
        for key, group in group_by_entity(failures, "host", "user", "src_ip").items():
            for window in _non_overlapping_threshold_windows(group, threshold, window_seconds):
                matches.append(
                    _make_match(
                        rule,
                        case_id,
                        window,
                        reason=(
                            f"Observed {len(window)} failed logons for one user, source IP, "
                            f"and host within {window_seconds} seconds."
                        ),
                        metadata={"correlation_key": list(key), "threshold": threshold},
                    )
                )
        return matches

    def _r002_failed_then_success(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        required = _parameter_int(rule, "required_failed_logins")
        window_seconds = _parameter_int(rule, "success_window_seconds")
        auth_events = [
            event
            for event in events
            if event.event_type in {EventType.FAILED_LOGON, EventType.SUCCESSFUL_LOGON}
        ]
        matches: list[RuleMatch] = []
        for key, group in group_by_entity(auth_events, "host", "user", "src_ip").items():
            failures = [event for event in group if event.event_type == EventType.FAILED_LOGON]
            successes = [event for event in group if event.event_type == EventType.SUCCESSFUL_LOGON]
            consumed: set[str] = set()
            for success in successes:
                preceding = [
                    event
                    for event in failures
                    if event.event_id not in consumed
                    and 0 <= (success.timestamp - event.timestamp).total_seconds() <= window_seconds
                ]
                if len(preceding) < required:
                    continue
                consumed.update(event.event_id for event in preceding)
                matches.append(
                    _make_match(
                        rule,
                        case_id,
                        [*preceding, success],
                        reason=(
                            f"A successful logon followed {len(preceding)} failures for the "
                            f"same user, source IP, and host within {window_seconds} seconds."
                        ),
                        metadata={"correlation_key": list(key), "threshold": required},
                    )
                )
        return matches

    def _r003_powershell_execution(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        names = _casefold_set(rule, "process_names")
        return [
            _make_match(
                rule,
                case_id,
                [event],
                reason="Observed PowerShell process creation; this is a low-level signal only.",
                metadata={"normalized_process_name": normalize_process_name(event.process_name)},
            )
            for event in events
            if event.event_type == EventType.PROCESS_CREATE
            and normalize_process_name(event.process_name) in names
        ]

    def _r004_office_to_interpreter(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        parents = _casefold_set(rule, "parent_process_names")
        children = _casefold_set(rule, "child_process_names")
        window_seconds = _parameter_int(rule, "window_seconds")
        process_events = [event for event in events if event.event_type == EventType.PROCESS_CREATE]
        parent_events = [
            event
            for event in process_events
            if normalize_process_name(event.process_name) in parents
        ]
        child_events = [
            event
            for event in process_events
            if normalize_process_name(event.process_name) in children
        ]
        pairs = find_followed_by(
            parent_events,
            child_events,
            same_fields=("host",),
            window_seconds=window_seconds,
            predicate=match_parent_child,
        )
        return [
            _make_match(
                rule,
                case_id,
                pair,
                reason="An Office process created a script interpreter with a validated relation.",
                metadata={"correlation_key": [pair[0].host, pair[0].process_id]},
            )
            for pair in pairs
        ]

    def _process_to_network(
        self,
        rule: DetectionRule,
        case_id: str,
        events: list[SecurityEvent],
        *,
        process_names: set[str] | None = None,
    ) -> list[RuleMatch]:
        window_seconds = _parameter_int(rule, "window_seconds")
        internal_cidrs = _parameter_strings(rule, "internal_cidrs")
        process_events = [
            event
            for event in events
            if event.event_type == EventType.PROCESS_CREATE
            and (
                process_names is None or normalize_process_name(event.process_name) in process_names
            )
        ]
        network_events = [
            event
            for event in events
            if event.event_type == EventType.NETWORK_CONNECTION
            and _is_external_ip(event.dst_ip, internal_cidrs)
        ]
        pairs = find_followed_by(
            process_events,
            network_events,
            same_fields=("host", "process_id"),
            window_seconds=window_seconds,
            predicate=match_same_process,
        )
        grouped: defaultdict[str, list[SecurityEvent]] = defaultdict(list)
        processes: dict[str, SecurityEvent] = {}
        for process, network in pairs:
            if _trusted_context(process, [network], rule):
                continue
            processes[process.event_id] = process
            grouped[process.event_id].append(network)
        return [
            _make_match(
                rule,
                case_id,
                [processes[process_id], *networks],
                reason=(
                    "A process was followed by an external network connection using the same "
                    "host and process ID."
                ),
                metadata={
                    "correlation_key": [
                        processes[process_id].host,
                        processes[process_id].process_id,
                    ]
                },
            )
            for process_id, networks in sorted(grouped.items())
        ]

    def _r005_process_to_network(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        return self._process_to_network(rule, case_id, events)

    def _r006_powershell_to_network(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        return self._process_to_network(
            rule,
            case_id,
            events,
            process_names=_casefold_set(rule, "process_names"),
        )

    def _r007_external_login_to_process(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        window_seconds = _parameter_int(rule, "window_seconds")
        internal_cidrs = _parameter_strings(rule, "internal_cidrs")
        logins = [
            event
            for event in events
            if event.event_type == EventType.SUCCESSFUL_LOGON
            and _is_external_ip(event.src_ip, internal_cidrs)
        ]
        processes = [event for event in events if event.event_type == EventType.PROCESS_CREATE]
        pairs = find_followed_by(
            logins,
            processes,
            same_fields=("host", "user"),
            window_seconds=window_seconds,
        )
        return [
            _make_match(
                rule,
                case_id,
                pair,
                reason=(
                    "An external successful login was followed by process activity for the "
                    "same user and host."
                ),
                metadata={"correlation_key": [pair[0].host, pair[0].user]},
            )
            for pair in pairs
        ]

    def _r008_scheduled_task_chain(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        window_seconds = _parameter_int(rule, "window_seconds")
        task_field = rule.parameters.get("task_name_field")
        if not isinstance(task_field, str) or not task_field:
            raise ValueError(f"{rule.rule_id}.task_name_field must be a string")
        creations = [
            event for event in events if event.event_type == EventType.SCHEDULED_TASK_CREATE
        ]
        executions = [
            event for event in events if event.event_type == EventType.SCHEDULED_TASK_EXECUTE
        ]

        def same_task(first: SecurityEvent, later: SecurityEvent) -> bool:
            task_name = first.raw.get(task_field)
            return bool(task_name and task_name == later.raw.get(task_field))

        pairs = find_followed_by(
            creations,
            executions,
            same_fields=("host",),
            window_seconds=window_seconds,
            predicate=same_task,
        )
        return [
            _make_match(
                rule,
                case_id,
                pair,
                reason="A scheduled task was created and later executed on the same host.",
                metadata={"correlation_key": [pair[0].host, pair[0].raw.get(task_field)]},
            )
            for pair in pairs
        ]

    def _r009_dns_to_network(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        window_seconds = _parameter_int(rule, "window_seconds")
        internal_cidrs = _parameter_strings(rule, "internal_cidrs")
        processes = [event for event in events if event.event_type == EventType.PROCESS_CREATE]
        dns_events = [event for event in events if event.event_type == EventType.DNS_QUERY]
        networks = [
            event
            for event in events
            if event.event_type == EventType.NETWORK_CONNECTION
            and _is_external_ip(event.dst_ip, internal_cidrs)
        ]
        triples: list[list[SecurityEvent]] = []
        for process, dns in find_followed_by(
            processes,
            dns_events,
            same_fields=("host", "process_id"),
            window_seconds=window_seconds,
            predicate=match_same_process,
        ):
            related_networks = [
                network
                for network in networks
                if match_same_process(process, network)
                and dns.timestamp <= network.timestamp
                and (network.timestamp - process.timestamp).total_seconds() <= window_seconds
                and dns.dst_domain == network.dst_domain
            ]
            if not related_networks or _trusted_context(process, [dns, *related_networks], rule):
                continue
            triples.append([process, dns, *related_networks])
        return [
            _make_match(
                rule,
                case_id,
                triple,
                reason=(
                    "A process performed DNS resolution and then connected to the resolved "
                    "external destination using the same process ID."
                ),
                metadata={"correlation_key": [triple[0].host, triple[0].process_id]},
            )
            for triple in triples
        ]

    def _r010_command_marker(
        self, rule: DetectionRule, case_id: str, events: list[SecurityEvent]
    ) -> list[RuleMatch]:
        markers = _casefold_set(rule, "exact_markers")
        process_names = _casefold_set(rule, "process_names")
        matches: list[RuleMatch] = []
        for event in events:
            if normalize_process_name(event.process_name) not in process_names:
                continue
            command_line = (event.command_line or "").casefold()
            matched = sorted(marker for marker in markers if marker in command_line)
            if not matched:
                continue
            matches.append(
                _make_match(
                    rule,
                    case_id,
                    [event],
                    reason="A configured exact synthetic command marker was observed.",
                    metadata={"matched_markers": matched},
                )
            )
        return matches

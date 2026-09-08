"""Deterministic scenario-based synthetic security event generation."""

import hashlib
import ipaddress
import json
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from investigation_agent.events.schemas import (
    CaseEntities,
    CaseMetadata,
    DatasetSummary,
    EventType,
    GeneratedGroundTruth,
    IncidentCase,
    ScenarioCatalog,
    ScenarioTemplate,
    SecurityEvent,
    SourceType,
)
from investigation_agent.ingestion.utils import atomic_write_bytes

_BASE_TIME = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
_SAFE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
_SAFE_DOMAIN_SUFFIXES = (".example.com", ".example.net", ".example.org")
_NOISE_PROCESSES = ("explorer.exe", "browser.exe", "teams.exe", "services.exe")


@dataclass
class EventDraft:
    """Internal event before deterministic IDs and absolute timestamps are assigned."""

    offset_seconds: int
    role: str
    relevant: bool
    values: dict[str, Any]
    duplicate_of_role: str | None = None
    insertion_order: int = field(default=0)


def _case_seed(seed: int, scenario_id: str, variant: int) -> int:
    """Derive independent stable randomness for one template variant."""

    digest = hashlib.sha256(f"{seed}:{scenario_id}:{variant}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _synthetic_hash(marker: str) -> str:
    return hashlib.sha256(f"synthetic:{marker}".encode()).hexdigest()


def _process_id(rng: random.Random) -> str:
    return str(rng.randint(1200, 64000))


def _raw(source_event_id: str, **extra: Any) -> dict[str, Any]:
    return {"synthetic": True, "source_event_id": source_event_id, **extra}


def _resolve_entities(template: ScenarioTemplate, rng: random.Random, variant: int) -> CaseEntities:
    """Resolve semantic template selectors to safe fictional entities."""

    host_prefix = "SRV" if template.entities.host == "server" else "WS"
    host = f"{host_prefix}-{rng.randint(1, 90):02d}"
    user_prefix = {
        "admin_user": "admin",
        "service_account": "svc-update",
        "standard_user": "user",
    }.get(template.entities.user, "user")
    user = f"{user_prefix}{rng.randint(1, 40):02d}"
    src_ip = (
        f"203.0.113.{20 + rng.randint(0, 180)}"
        if template.entities.src_ip == "external"
        else f"10.{20 + variant}.{rng.randint(1, 20)}.{rng.randint(10, 220)}"
    )
    dst_ip = f"198.51.100.{20 + rng.randint(0, 180)}"
    domain = {
        "browser": f"portal-{rng.randint(1, 20)}.example.com",
        "management": f"management-{rng.randint(1, 20)}.example.net",
        "update": f"updates-{rng.randint(1, 20)}.example.com",
    }.get(template.entities.domain, f"telemetry-{rng.randint(1, 20)}.example.net")
    process = {
        "browser": "browser.exe",
        "command_shell": "cmd.exe",
        "office": rng.choice(("WINWORD.EXE", "EXCEL.EXE")),
        "powershell": "powershell.exe",
        "scheduled_task": "taskeng.exe",
        "script_host": "wscript.exe",
        "updater": "updater.exe",
    }.get(template.entities.process)
    return CaseEntities(
        host=host,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        process=process,
    )


def _auth(
    offset: int,
    role: str,
    entities: CaseEntities,
    *,
    success: bool,
    relevant: bool = True,
    user: str | None = None,
) -> EventDraft:
    source_event_id = "4624" if success else "4625"
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=relevant,
        values={
            "source_type": SourceType.WINDOWS_SECURITY,
            "source_event_id": source_event_id,
            "event_type": EventType.SUCCESSFUL_LOGON if success else EventType.FAILED_LOGON,
            "host": entities.host,
            "user": user or entities.user,
            "src_ip": entities.src_ip,
            "raw": _raw(source_event_id, logon_type=3, status="success" if success else "failure"),
        },
    )


def _process(
    offset: int,
    role: str,
    entities: CaseEntities,
    rng: random.Random,
    *,
    name: str,
    parent_name: str,
    command_line: str,
    process_id: str | None = None,
    parent_process_id: str | None = None,
    relevant: bool = True,
) -> EventDraft:
    process_id = process_id or _process_id(rng)
    parent_process_id = parent_process_id or _process_id(rng)
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=relevant,
        values={
            "source_type": SourceType.SYSMON,
            "source_event_id": "1",
            "event_type": EventType.PROCESS_CREATE,
            "host": entities.host,
            "user": entities.user,
            "process_name": name,
            "parent_process_name": parent_name,
            "process_id": process_id,
            "parent_process_id": parent_process_id,
            "command_line": command_line,
            "raw": _raw("1", image=name, parent_image=parent_name),
        },
    )


def _dns(
    offset: int,
    role: str,
    entities: CaseEntities,
    *,
    process_name: str,
    process_id: str,
    domain: str | None = None,
    relevant: bool = True,
) -> EventDraft:
    destination = domain or entities.domain
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=relevant,
        values={
            "source_type": SourceType.DNS,
            "source_event_id": "DNS_QUERY",
            "event_type": EventType.DNS_QUERY,
            "host": entities.host,
            "user": entities.user,
            "process_name": process_name,
            "process_id": process_id,
            "src_ip": entities.src_ip,
            "dst_domain": destination,
            "raw": _raw("DNS_QUERY", query=destination, response=entities.dst_ip),
        },
    )


def _network(
    offset: int,
    role: str,
    entities: CaseEntities,
    *,
    process_name: str,
    process_id: str,
    port: int = 443,
    relevant: bool = True,
) -> EventDraft:
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=relevant,
        values={
            "source_type": SourceType.NETWORK,
            "source_event_id": "FLOW",
            "event_type": EventType.NETWORK_CONNECTION,
            "host": entities.host,
            "user": entities.user,
            "process_name": process_name,
            "process_id": process_id,
            "src_ip": entities.src_ip,
            "dst_ip": entities.dst_ip,
            "dst_port": port,
            "dst_domain": entities.domain,
            "raw": _raw("FLOW", action="allowed", protocol="tcp"),
        },
    )


def _file(
    offset: int,
    role: str,
    entities: CaseEntities,
    *,
    process_name: str,
    process_id: str,
    marker: str,
    relevant: bool = True,
) -> EventDraft:
    path = f"C:\\Synthetic\\{marker}.txt"
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=relevant,
        values={
            "source_type": SourceType.SYSMON,
            "source_event_id": "11",
            "event_type": EventType.FILE_CREATE,
            "host": entities.host,
            "user": entities.user,
            "process_name": process_name,
            "process_id": process_id,
            "file_path": path,
            "file_hash": _synthetic_hash(marker),
            "raw": _raw("11", target_filename=path),
        },
    )


def _scheduled_task_create(offset: int, role: str, entities: CaseEntities) -> EventDraft:
    return EventDraft(
        offset_seconds=offset,
        role=role,
        relevant=True,
        values={
            "source_type": SourceType.WINDOWS_SECURITY,
            "source_event_id": "4698",
            "event_type": EventType.SCHEDULED_TASK_CREATE,
            "host": entities.host,
            "user": entities.user,
            "raw": _raw("4698", task_name="SyntheticTelemetryTask"),
        },
    )


def _build_relevant_events(
    template: ScenarioTemplate,
    entities: CaseEntities,
    rng: random.Random,
    variant: int,
) -> list[EventDraft]:
    """Create the ordered story for one of the twelve supported templates."""

    scenario_id = template.scenario_id
    jitter = rng.randint(0, 12)
    if scenario_id == "S01":
        attempts = 5 + variant - 1
        return [
            _auth(jitter + index * 45, "failed_logon", entities, success=False)
            for index in range(attempts)
        ]
    if scenario_id == "S02":
        attempts = 5 + variant - 1
        events = [
            _auth(jitter + index * 35, "failed_logon", entities, success=False)
            for index in range(attempts)
        ]
        events.append(
            _auth(jitter + attempts * 35 + 20, "successful_logon", entities, success=True)
        )
        return events
    if scenario_id == "S03":
        parent_pid, powershell_pid = _process_id(rng), _process_id(rng)
        return [
            _process(
                jitter,
                "parent_process",
                entities,
                rng,
                name="explorer.exe",
                parent_name="userinit.exe",
                command_line="explorer.exe <synthetic-session>",
                process_id=parent_pid,
            ),
            _process(
                jitter + 40,
                "powershell_process",
                entities,
                rng,
                name="powershell.exe",
                parent_name="explorer.exe",
                command_line='powershell.exe -NoProfile -Command "<synthetic-action>"',
                process_id=powershell_pid,
                parent_process_id=parent_pid,
            ),
            _process(
                jitter + 65,
                "console_process",
                entities,
                rng,
                name="conhost.exe",
                parent_name="powershell.exe",
                command_line="conhost.exe <synthetic-console>",
                parent_process_id=powershell_pid,
            ),
        ]
    if scenario_id == "S04":
        office_pid, powershell_pid = _process_id(rng), _process_id(rng)
        office_name = entities.process or "WINWORD.EXE"
        return [
            _process(
                jitter,
                "office_process",
                entities,
                rng,
                name=office_name,
                parent_name="explorer.exe",
                command_line=f"{office_name} <synthetic-document>",
                process_id=office_pid,
            ),
            _process(
                jitter + 35,
                "powershell_process",
                entities,
                rng,
                name="powershell.exe",
                parent_name=office_name,
                command_line='powershell.exe -Command "<synthetic-office-action>"',
                process_id=powershell_pid,
                parent_process_id=office_pid,
            ),
            _process(
                jitter + 55,
                "console_process",
                entities,
                rng,
                name="conhost.exe",
                parent_name="powershell.exe",
                command_line="conhost.exe <synthetic-console>",
                parent_process_id=powershell_pid,
            ),
        ]
    if scenario_id == "S05":
        process_id = _process_id(rng)
        return [
            _process(
                jitter,
                "powershell_process",
                entities,
                rng,
                name="powershell.exe",
                parent_name="explorer.exe",
                command_line='powershell.exe -Command "<synthetic-network-action>"',
                process_id=process_id,
            ),
            _dns(
                jitter + 30,
                "dns_query",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
            ),
            _network(
                jitter + 50,
                "network_connection",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
            ),
            _file(
                jitter + 85,
                "file_create",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
                marker=f"s05-v{variant:02d}",
            ),
        ]
    if scenario_id == "S06":
        process_id = _process_id(rng)
        return [
            _auth(jitter, "external_login", entities, success=True),
            _process(
                jitter + 50,
                "process_activity",
                entities,
                rng,
                name="cmd.exe",
                parent_name="explorer.exe",
                command_line="cmd.exe /c echo <synthetic-action>",
                process_id=process_id,
            ),
            _network(
                jitter + 85,
                "network_connection",
                entities,
                process_name="cmd.exe",
                process_id=process_id,
            ),
        ]
    if scenario_id == "S07":
        task_pid = _process_id(rng)
        task_process = _process_id(rng)
        execution = EventDraft(
            offset_seconds=jitter + 300,
            role="scheduled_task_execution",
            relevant=True,
            values={
                "source_type": SourceType.SYSMON,
                "source_event_id": "1",
                "event_type": EventType.SCHEDULED_TASK_EXECUTE,
                "host": entities.host,
                "user": entities.user,
                "process_name": "taskeng.exe",
                "parent_process_name": "svchost.exe",
                "process_id": task_pid,
                "parent_process_id": _process_id(rng),
                "command_line": "taskeng.exe <synthetic-task>",
                "raw": _raw("1", task_name="SyntheticTelemetryTask"),
            },
        )
        return [
            _scheduled_task_create(jitter, "scheduled_task_creation", entities),
            execution,
            _process(
                jitter + 325,
                "task_process",
                entities,
                rng,
                name="cmd.exe",
                parent_name="taskeng.exe",
                command_line="cmd.exe /c echo <synthetic-task-action>",
                process_id=task_process,
                parent_process_id=task_pid,
            ),
        ]
    if scenario_id == "S08":
        process_id = _process_id(rng)
        return [
            _process(
                jitter,
                "originating_process",
                entities,
                rng,
                name="wscript.exe",
                parent_name="explorer.exe",
                command_line="wscript.exe <synthetic-script>",
                process_id=process_id,
            ),
            _dns(
                jitter + 25,
                "dns_query",
                entities,
                process_name="wscript.exe",
                process_id=process_id,
            ),
            _network(
                jitter + 50,
                "network_connection",
                entities,
                process_name="wscript.exe",
                process_id=process_id,
            ),
        ]
    if scenario_id == "B01":
        return [
            _auth(jitter + index * 120, "successful_logon", entities, success=True)
            for index in range(3)
        ]
    if scenario_id == "B02":
        process_id = _process_id(rng)
        return [
            _process(
                jitter,
                "admin_powershell",
                entities,
                rng,
                name="powershell.exe",
                parent_name="management-agent.exe",
                command_line='powershell.exe -Command "<approved-maintenance>"',
                process_id=process_id,
            ),
            _dns(
                jitter + 30,
                "management_dns",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
            ),
            _network(
                jitter + 50,
                "management_network",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
            ),
            _file(
                jitter + 90,
                "maintenance_file",
                entities,
                process_name="powershell.exe",
                process_id=process_id,
                marker=f"approved-maintenance-v{variant:02d}",
            ),
        ]
    if scenario_id == "B03":
        process_id = _process_id(rng)
        return [
            _process(
                jitter,
                "browser_process",
                entities,
                rng,
                name="browser.exe",
                parent_name="explorer.exe",
                command_line="browser.exe --synthetic-profile",
                process_id=process_id,
            ),
            _dns(
                jitter + 20,
                "browser_dns",
                entities,
                process_name="browser.exe",
                process_id=process_id,
            ),
            _network(
                jitter + 40,
                "browser_network",
                entities,
                process_name="browser.exe",
                process_id=process_id,
            ),
        ]
    if scenario_id == "B04":
        process_id = _process_id(rng)
        return [
            _process(
                jitter,
                "update_process",
                entities,
                rng,
                name="updater.exe",
                parent_name="services.exe",
                command_line="updater.exe --synthetic-check",
                process_id=process_id,
            ),
            _dns(
                jitter + 20,
                "update_dns",
                entities,
                process_name="updater.exe",
                process_id=process_id,
            ),
            _network(
                jitter + 45,
                "update_network",
                entities,
                process_name="updater.exe",
                process_id=process_id,
            ),
            _file(
                jitter + 100,
                "update_file",
                entities,
                process_name="updater.exe",
                process_id=process_id,
                marker=f"approved-update-v{variant:02d}",
            ),
        ]
    raise ValueError(f"No event story builder for scenario {scenario_id}")


def _noise_events(
    entities: CaseEntities,
    rng: random.Random,
    *,
    count: int,
    relevant_start: int,
    relevant_end: int,
    variant: int,
) -> list[EventDraft]:
    """Create benign telemetry spread across and around the relevant sequence."""

    normal_count = count - 1 if variant == 3 else count
    offsets = [(relevant_start + relevant_end) // 2]
    offsets.extend(
        rng.randint(relevant_start - 300, relevant_end + 300) for _ in range(normal_count - 1)
    )
    events: list[EventDraft] = []
    for index, offset in enumerate(offsets, 1):
        role = f"noise_{index:03d}"
        if variant == 3 and index <= 2:
            choice = "process"
        elif variant == 3 and index % 5 == 0:
            choice = "login"
        else:
            choice = rng.choice(("process", "login", "dns", "network", "file"))
        background_user = entities.user if index % 5 else f"background{rng.randint(1, 20):02d}"
        if choice == "process":
            noise_entities = entities.model_copy(update={"user": background_user})
            event = _process(
                offset,
                role,
                noise_entities,
                rng,
                name=rng.choice(_NOISE_PROCESSES),
                parent_name="services.exe" if index % 2 else "explorer.exe",
                command_line="<synthetic-benign-process>",
                relevant=False,
            )
        elif choice == "login":
            noise_entities = entities.model_copy(update={"user": background_user})
            event = _auth(
                offset,
                role,
                noise_entities,
                success=True,
                relevant=False,
                user=background_user,
            )
        elif choice == "dns":
            event = _dns(
                offset,
                role,
                entities,
                process_name="browser.exe",
                process_id=_process_id(rng),
                domain=f"background-{rng.randint(1, 30)}.example.com",
                relevant=False,
            )
        elif choice == "network":
            event = _network(
                offset,
                role,
                entities,
                process_name="browser.exe",
                process_id=_process_id(rng),
                relevant=False,
            )
        else:
            event = _file(
                offset,
                role,
                entities,
                process_name="updater.exe",
                process_id=_process_id(rng),
                marker=f"noise-{index:03d}",
                relevant=False,
            )
        event.insertion_order = index
        events.append(event)

    if variant == 3:
        first = events[0]
        duplicate_values = {**first.values, "raw": dict(first.values["raw"])}
        duplicate_values["raw"]["synthetic_duplicate"] = True
        events.append(
            EventDraft(
                offset_seconds=first.offset_seconds,
                role="duplicate_event",
                relevant=False,
                values=duplicate_values,
                duplicate_of_role=first.role,
                insertion_order=normal_count + 1,
            )
        )
        if len(events) > 2:
            events[1].offset_seconds = events[0].offset_seconds
    return events


def _materialize_case(
    template: ScenarioTemplate,
    *,
    variant: int,
    seed: int,
    template_index: int,
) -> IncidentCase:
    variant_seed = _case_seed(seed, template.scenario_id, variant)
    rng = random.Random(variant_seed)
    entities = _resolve_entities(template, rng, variant)
    relevant = _build_relevant_events(template, entities, rng, variant)
    noise_count = rng.randint(20, 80)
    noise = _noise_events(
        entities,
        rng,
        count=noise_count,
        relevant_start=min(event.offset_seconds for event in relevant),
        relevant_end=max(event.offset_seconds for event in relevant),
        variant=variant,
    )
    drafts = [*relevant, *noise]
    for insertion_order, draft in enumerate(drafts):
        draft.insertion_order = insertion_order
    drafts.sort(key=lambda draft: (draft.offset_seconds, draft.insertion_order))

    base_time = _BASE_TIME + timedelta(
        days=template_index,
        hours=(variant - 1) * 3,
        seconds=rng.randint(0, 120),
    )
    case_id = f"INC-{template.scenario_id}-V{variant:02d}"
    role_map: defaultdict[str, list[str]] = defaultdict(list)
    events: list[SecurityEvent] = []
    draft_by_event_id: dict[str, EventDraft] = {}
    for index, draft in enumerate(drafts, 1):
        event_id = f"{case_id}-E{index:04d}"
        role_map[draft.role].append(event_id)
        labels = (
            ["relevant", "suspicious_sequence"]
            if draft.relevant and template.ground_truth.suspicious
            else ["relevant", "benign_control"]
            if draft.relevant
            else ["noise", "benign"]
        )
        events.append(
            SecurityEvent(
                event_id=event_id,
                timestamp=base_time + timedelta(seconds=draft.offset_seconds),
                scenario_id=template.scenario_id,
                ground_truth_labels=labels,
                **draft.values,
            )
        )
        draft_by_event_id[event_id] = draft

    for index, event in enumerate(events):
        draft = draft_by_event_id[event.event_id]
        if draft.duplicate_of_role:
            raw = dict(event.raw)
            raw["duplicate_of_event_id"] = role_map[draft.duplicate_of_role][0]
            events[index] = event.model_copy(update={"raw": raw})

    relevant_ids = [event.event_id for event in events if "relevant" in event.ground_truth_labels]
    canonical_ids = [event.event_id for event in events]
    input_ids = list(canonical_ids)
    missing_ids: list[str] = []
    edge_cases: list[str] = ["relevant_mixed_with_benign"]
    if variant == 2:
        rng.shuffle(input_ids)
        if input_ids == canonical_ids:
            input_ids = input_ids[1:] + input_ids[:1]
        edge_cases.append("out_of_order_input")
    if variant == 3:
        missing_id = next(
            event.event_id
            for event in events
            if event.ground_truth_labels == ["noise", "benign"]
            and not event.raw.get("synthetic_duplicate")
        )
        input_ids.remove(missing_id)
        missing_ids.append(missing_id)
        edge_cases.extend(
            [
                "duplicate_event",
                "missing_event_input",
                "multiple_users_same_host",
                "simultaneous_processes",
            ]
        )

    expected_roles = template.ground_truth.expected_event_roles
    missing_roles = sorted(role for role in expected_roles if not role_map.get(role))
    if missing_roles:
        raise ValueError(f"Scenario {template.scenario_id} did not generate roles {missing_roles}")
    selected_roles = {role: role_map[role] for role in expected_roles}
    return IncidentCase(
        scenario_id=template.scenario_id,
        variant_id=f"V{variant:02d}",
        case_id=case_id,
        metadata=CaseMetadata(
            template_name=template.name,
            template_description=template.description,
            seed=seed,
            variant_seed=variant_seed,
            entities=entities,
            noise_event_count=noise_count,
            relevant_event_count=len(relevant_ids),
            input_event_ids=input_ids,
            missing_event_ids=missing_ids,
            edge_cases=edge_cases,
        ),
        events=events,
        ground_truth=GeneratedGroundTruth(
            suspicious=template.ground_truth.suspicious,
            relevant_event_ids=relevant_ids,
            event_roles=selected_roles,
            expected_behaviors=template.ground_truth.expected_behaviors,
            expected_rule_ids=template.ground_truth.expected_rule_ids,
            expected_mitre=template.ground_truth.expected_mitre,
            expected_next_action_categories=(template.ground_truth.expected_next_action_categories),
        ),
    )


def generate_dataset(
    catalog: ScenarioCatalog,
    *,
    seed: int = 42,
    variants: int = 3,
) -> tuple[list[IncidentCase], DatasetSummary]:
    """Generate all configured templates and variants deterministically."""

    if not 1 <= variants <= 20:
        raise ValueError("variants must be between 1 and 20")
    cases = [
        _materialize_case(
            template,
            variant=variant,
            seed=seed,
            template_index=template_index,
        )
        for template_index, template in enumerate(catalog.templates)
        for variant in range(1, variants + 1)
    ]
    event_ids = [event.event_id for case in cases for event in case.events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event IDs must be unique across the complete dataset")
    counts = [len(case.events) for case in cases]
    summary = DatasetSummary(
        seed=seed,
        variants=variants,
        scenario_count=len(catalog.templates),
        case_count=len(cases),
        suspicious_case_count=sum(case.ground_truth.suspicious for case in cases),
        benign_case_count=sum(not case.ground_truth.suspicious for case in cases),
        total_events=sum(counts),
        average_events_per_case=round(sum(counts) / len(counts), 2),
        min_events_per_case=min(counts),
        max_events_per_case=max(counts),
    )
    return cases, summary


def validate_safe_dataset(cases: list[IncidentCase]) -> None:
    """Reject accidental real external indicators or executable command payloads."""

    forbidden_command_markers = (
        "http://",
        "https://",
        "downloadstring",
        "invoke-webrequest",
        "frombase64string",
    )
    for case in cases:
        for event in case.events:
            for value in (event.src_ip, event.dst_ip):
                if value:
                    address = ipaddress.ip_address(value)
                    if not any(address in network for network in _SAFE_NETWORKS):
                        raise ValueError(f"Unsafe synthetic IP address: {value}")
            if event.dst_domain and not event.dst_domain.endswith(_SAFE_DOMAIN_SUFFIXES):
                raise ValueError(f"Unsafe synthetic domain: {event.dst_domain}")
            command_line = (event.command_line or "").casefold()
            if any(marker in command_line for marker in forbidden_command_markers):
                raise ValueError(f"Unsafe synthetic command line in {event.event_id}")


def write_dataset(
    cases: list[IncidentCase],
    summary: DatasetSummary,
    *,
    output_path: Path,
    summary_path: Path,
) -> tuple[bool, bool]:
    """Persist stable JSONL and summary JSON, replacing files only when bytes differ."""

    validate_safe_dataset(cases)
    dataset_bytes = (
        "\n".join(case.model_dump_json(exclude_none=False) for case in cases) + "\n"
    ).encode("utf-8")
    summary_bytes = (
        json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    dataset_changed = not output_path.exists() or output_path.read_bytes() != dataset_bytes
    summary_changed = not summary_path.exists() or summary_path.read_bytes() != summary_bytes
    if dataset_changed:
        atomic_write_bytes(output_path, dataset_bytes)
    if summary_changed:
        atomic_write_bytes(summary_path, summary_bytes)
    return dataset_changed, summary_changed


def load_dataset(path: Path) -> list[IncidentCase]:
    """Load and validate generated incident JSONL for tests and later checkpoints."""

    cases: list[IncidentCase] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            cases.append(IncidentCase.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid incident JSONL at line {line_number}") from exc
    return cases

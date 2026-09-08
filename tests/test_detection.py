"""Checkpoint 4 deterministic detection, correlation, and case-building tests."""

from datetime import timedelta
from pathlib import Path

import pytest

from investigation_agent.detection.case_builder import build_investigation_case
from investigation_agent.detection.config import load_detection_config
from investigation_agent.detection.pipeline import (
    load_investigation_cases,
    observed_events,
    process_incidents,
    write_detection_outputs,
)
from investigation_agent.detection.rules import DetectionEngine
from investigation_agent.events.scenario_templates import configured_mitre_ids
from investigation_agent.events.schemas import IncidentCase, SecurityEvent
from investigation_agent.events.synthetic_generator import load_dataset

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "config" / "correlation_rules.yaml"
SOURCES_PATH = PROJECT_ROOT / "config" / "sources.yaml"
DATASET_PATH = PROJECT_ROOT / "data" / "synthetic" / "incidents.jsonl"


@pytest.fixture(scope="module")
def detection_config():
    return load_detection_config(
        RULES_PATH,
        allowed_mitre_ids=configured_mitre_ids(SOURCES_PATH),
    )


@pytest.fixture(scope="module")
def engine(detection_config):
    return DetectionEngine(detection_config)


@pytest.fixture(scope="module")
def incidents() -> list[IncidentCase]:
    return load_dataset(DATASET_PATH)


def _incident(
    incidents: list[IncidentCase], scenario_id: str, variant_id: str = "V01"
) -> IncidentCase:
    return next(
        incident
        for incident in incidents
        if incident.scenario_id == scenario_id and incident.variant_id == variant_id
    )


def _role_events(incident: IncidentCase, *roles: str) -> list[SecurityEvent]:
    event_ids = {event_id for role in roles for event_id in incident.ground_truth.event_roles[role]}
    return [event for event in incident.events if event.event_id in event_ids]


def _rule_ids(engine: DetectionEngine, case_id: str, events) -> set[str]:
    _, matches = engine.evaluate(case_id, events)
    return {match.rule_id for match in matches}


def test_rule_config_defines_ten_rules_and_valid_mitre(detection_config) -> None:
    assert list(detection_config.rules) == [f"R{index:03d}" for index in range(1, 11)]
    assert detection_config.severity_weights == {
        "informational": 1,
        "low": 2,
        "medium": 4,
        "high": 7,
    }


def test_r001_threshold(engine, incidents) -> None:
    incident = _incident(incidents, "S01")
    failures = _role_events(incident, "failed_logon")
    assert "R001" not in _rule_ids(engine, incident.case_id, failures[:4])
    assert "R001" in _rule_ids(engine, incident.case_id, failures[:5])


def test_r001_time_window(engine, incidents) -> None:
    incident = _incident(incidents, "S01")
    failures = _role_events(incident, "failed_logon")[:5]
    delayed = failures[-1].model_copy(
        update={"timestamp": failures[0].timestamp + timedelta(seconds=301)}
    )
    assert "R001" not in _rule_ids(engine, incident.case_id, [*failures[:-1], delayed])


def test_r002_failed_then_success_contains_all_evidence(engine, incidents) -> None:
    incident = _incident(incidents, "S02")
    events = _role_events(incident, "failed_logon", "successful_logon")
    _, matches = engine.evaluate(incident.case_id, events)
    match = next(item for item in matches if item.rule_id == "R002")
    assert set(match.matched_event_ids) == {event.event_id for event in events}
    assert match.start_time < match.end_time


@pytest.mark.parametrize("field,value", [("user", "other-user"), ("src_ip", "192.0.2.250")])
def test_r002_does_not_correlate_wrong_identity(engine, incidents, field: str, value: str) -> None:
    incident = _incident(incidents, "S02")
    events = _role_events(incident, "failed_logon", "successful_logon")
    success = next(event for event in events if event.event_type == "successful_logon")
    changed = success.model_copy(update={field: value})
    input_events = [changed if event.event_id == success.event_id else event for event in events]
    assert "R002" not in _rule_ids(engine, incident.case_id, input_events)


def test_r004_requires_valid_parent_child_relation(engine, incidents) -> None:
    incident = _incident(incidents, "S04")
    events = _role_events(incident, "office_process", "powershell_process")
    assert "R004" in _rule_ids(engine, incident.case_id, events)
    child = events[-1].model_copy(update={"parent_process_id": "999999"})
    assert "R004" not in _rule_ids(engine, incident.case_id, [events[0], child])


def test_r005_and_r006_require_same_process(engine, incidents) -> None:
    incident = _incident(incidents, "S05")
    events = _role_events(incident, "powershell_process", "network_connection")
    assert {"R005", "R006"} <= _rule_ids(engine, incident.case_id, events)
    network = events[-1].model_copy(update={"process_id": "999999"})
    rules = _rule_ids(engine, incident.case_id, [events[0], network])
    assert "R005" not in rules
    assert "R006" not in rules


def test_r007_external_login_followed_by_same_user_process(engine, incidents) -> None:
    incident = _incident(incidents, "S06")
    events = _role_events(incident, "external_login", "process_activity")
    assert "R007" in _rule_ids(engine, incident.case_id, events)
    process = events[-1].model_copy(update={"user": "different-user"})
    assert "R007" not in _rule_ids(engine, incident.case_id, [events[0], process])


def test_r008_scheduled_task_chain(engine, incidents) -> None:
    incident = _incident(incidents, "S07")
    events = _role_events(incident, "scheduled_task_creation", "scheduled_task_execution")
    assert "R008" in _rule_ids(engine, incident.case_id, events)
    execution = events[-1].model_copy(
        update={"raw": {**events[-1].raw, "task_name": "DifferentSyntheticTask"}}
    )
    assert "R008" not in _rule_ids(engine, incident.case_id, [events[0], execution])


def test_r009_dns_network_chain_and_missing_event(engine, incidents) -> None:
    incident = _incident(incidents, "S08")
    events = _role_events(incident, "originating_process", "dns_query", "network_connection")
    assert "R009" in _rule_ids(engine, incident.case_id, events)
    without_network = [event for event in events if event.event_type != "network_connection"]
    rules = _rule_ids(engine, incident.case_id, without_network)
    assert "R009" not in rules
    assert "R005" not in rules


def test_out_of_order_input_has_identical_matches(engine, incidents) -> None:
    incident = _incident(incidents, "S05")
    events = _role_events(
        incident,
        "powershell_process",
        "dns_query",
        "network_connection",
        "file_create",
    )
    canonical, first = engine.evaluate(incident.case_id, events)
    reversed_events, second = engine.evaluate(incident.case_id, reversed(events))
    assert [event.event_id for event in canonical] == [event.event_id for event in reversed_events]
    assert [match.model_dump() for match in first] == [match.model_dump() for match in second]


def test_duplicate_failure_does_not_cross_r001_threshold(engine, incidents) -> None:
    incident = _incident(incidents, "S01")
    failures = _role_events(incident, "failed_logon")[:4]
    original = failures[0]
    duplicate = original.model_copy(
        update={
            "event_id": "INC-S01-V01-E9999",
            "raw": {
                **original.raw,
                "synthetic_duplicate": True,
                "duplicate_of_event_id": original.event_id,
            },
        }
    )
    canonical, matches = engine.evaluate(incident.case_id, [*failures, duplicate])
    assert len(canonical) == 4
    assert "R001" not in {match.rule_id for match in matches}


def test_multiple_users_on_same_host_do_not_merge_auth_groups(engine, incidents) -> None:
    incident = _incident(incidents, "S02")
    failures = _role_events(incident, "failed_logon")[:5]
    split = [
        event.model_copy(update={"user": "user-a" if index < 3 else "user-b"})
        for index, event in enumerate(failures)
    ]
    success = _role_events(incident, "successful_logon")[0].model_copy(update={"user": "user-a"})
    rules = _rule_ids(engine, incident.case_id, [*split, success])
    assert "R001" not in rules
    assert "R002" not in rules


def test_simultaneous_processes_keep_process_correlation_isolated(engine, incidents) -> None:
    incident = _incident(incidents, "S05")
    process, network = _role_events(incident, "powershell_process", "network_connection")
    simultaneous = process.model_copy(
        update={
            "event_id": "INC-S05-V01-E9999",
            "process_name": "explorer.exe",
            "process_id": "999999",
            "command_line": "<synthetic-benign-process>",
        }
    )
    _, matches = engine.evaluate(incident.case_id, [simultaneous, process, network])
    match = next(item for item in matches if item.rule_id == "R005")
    assert process.event_id in match.matched_event_ids
    assert simultaneous.event_id not in match.matched_event_ids


def test_b02_only_produces_low_non_escalated_powershell_behavior(
    detection_config, incidents
) -> None:
    incident = _incident(incidents, "B02")
    cases, _ = process_incidents([incident], detection_config)
    case = cases[0]
    assert {match.rule_id for match in case.rule_matches} == {"R003"}
    assert [behavior.behavior_type for behavior in case.candidate_behaviors] == [
        "powershell_execution"
    ]
    assert case.severity_score == 2
    assert case.severity_label == "low"
    assert case.escalated is False


def test_rule_match_ids_are_deterministic(engine, incidents) -> None:
    incident = _incident(incidents, "S02")
    events = observed_events(incident)
    _, first = engine.evaluate(incident.case_id, events)
    _, second = engine.evaluate(incident.case_id, reversed(events))
    assert [match.match_id for match in first] == [match.match_id for match in second]


def test_runtime_case_builder_does_not_require_ground_truth(
    detection_config, engine, incidents
) -> None:
    incident = _incident(incidents, "S05")
    case = build_investigation_case(
        case_id=incident.case_id,
        source_scenario_id=incident.scenario_id,
        events=observed_events(incident),
        engine=engine,
        config=detection_config,
    )
    assert case.ground_truth is None
    assert case.severity_label == "high"
    assert case.escalated is True


def test_all_cases_meet_detection_targets_and_references(detection_config, incidents) -> None:
    cases, summary = process_incidents(incidents, detection_config)
    assert summary.processed_cases == 36
    assert summary.suspicious_cases_detected == 24
    assert summary.suspicious_cases_missed == 0
    assert summary.benign_cases_escalated == 0
    assert summary.expected_rule_coverage >= 0.9
    assert summary.unexpected_rule_hits == 0
    assert summary.failures == []
    for case in cases:
        event_ids = {event.event_id for event in case.events}
        match_ids = {match.match_id for match in case.rule_matches}
        assert all(set(match.matched_event_ids) <= event_ids for match in case.rule_matches)
        assert all(
            set(behavior.supporting_event_ids) <= event_ids
            and set(behavior.supporting_rule_match_ids) <= match_ids
            for behavior in case.candidate_behaviors
        )


def test_detection_output_is_idempotent_and_loadable(
    detection_config, incidents, tmp_path: Path
) -> None:
    cases, summary = process_incidents(incidents, detection_config)
    output = tmp_path / "cases.jsonl"
    summary_output = tmp_path / "detection_summary.json"
    assert write_detection_outputs(
        cases, summary, output_path=output, summary_path=summary_output
    ) == (True, True)
    first_bytes = output.read_bytes()
    assert write_detection_outputs(
        cases, summary, output_path=output, summary_path=summary_output
    ) == (False, False)
    assert output.read_bytes() == first_bytes
    assert load_investigation_cases(output) == cases

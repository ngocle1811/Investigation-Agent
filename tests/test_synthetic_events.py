"""Checkpoint 3 schema, scenario, determinism, and safety tests."""

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from investigation_agent.events.scenario_templates import (
    configured_mitre_ids,
    load_scenario_catalog,
)
from investigation_agent.events.schemas import EventType, SecurityEvent, SourceType
from investigation_agent.events.synthetic_generator import (
    generate_dataset,
    load_dataset,
    validate_safe_dataset,
    write_dataset,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_PATH = PROJECT_ROOT / "config" / "synthetic_scenarios.yaml"
SOURCES_PATH = PROJECT_ROOT / "config" / "sources.yaml"
SAFE_NETWORKS = tuple(
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


@pytest.fixture(scope="module")
def catalog():
    """Load the real catalog against the real configured MITRE subset."""

    return load_scenario_catalog(
        SCENARIOS_PATH,
        allowed_mitre_ids=configured_mitre_ids(SOURCES_PATH),
    )


@pytest.fixture(scope="module")
def generated(catalog):
    """Generate the canonical three-variant benchmark once per module."""

    return generate_dataset(catalog, seed=42, variants=3)


def _event(**updates: object) -> SecurityEvent:
    values = {
        "event_id": "INC-B01-V01-E0001",
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
        "source_type": SourceType.WINDOWS_SECURITY,
        "source_event_id": "4624",
        "event_type": EventType.SUCCESSFUL_LOGON,
        "host": "WS-01",
        "user": "user01",
        "src_ip": "10.1.1.10",
        "scenario_id": "B01",
    }
    values.update(updates)
    return SecurityEvent.model_validate(values)


def _case(cases, scenario_id: str, variant_id: str = "V01"):
    return next(
        case for case in cases if case.scenario_id == scenario_id and case.variant_id == variant_id
    )


def test_security_event_supports_nullable_source_fields_and_strict_requirements() -> None:
    event = _event()
    assert event.process_name is None
    assert event.dst_domain is None

    with pytest.raises(ValidationError, match="timezone-aware"):
        _event(timestamp=datetime(2026, 1, 1))
    with pytest.raises(ValidationError, match="network connections require"):
        _event(
            source_type=SourceType.NETWORK,
            source_event_id="FLOW",
            event_type=EventType.NETWORK_CONNECTION,
            dst_ip=None,
            dst_port=None,
        )


def test_catalog_has_expected_templates_and_valid_mitre_subset(catalog) -> None:
    suspicious = [item for item in catalog.templates if item.category == "suspicious"]
    benign = [item for item in catalog.templates if item.category == "benign"]
    allowed = configured_mitre_ids(SOURCES_PATH)
    mapped = {
        technique for item in catalog.templates for technique in item.ground_truth.expected_mitre
    }
    assert [item.scenario_id for item in suspicious] == [f"S{index:02d}" for index in range(1, 9)]
    assert [item.scenario_id for item in benign] == [f"B{index:02d}" for index in range(1, 5)]
    assert mapped <= allowed
    with pytest.raises(ValueError, match="outside the configured knowledge subset"):
        load_scenario_catalog(SCENARIOS_PATH, allowed_mitre_ids=set())


def test_generation_is_deterministic_and_seed_sensitive(catalog) -> None:
    first_cases, first_summary = generate_dataset(catalog, seed=42, variants=3)
    second_cases, second_summary = generate_dataset(catalog, seed=42, variants=3)
    other_cases, other_summary = generate_dataset(catalog, seed=43, variants=3)
    first_json = [case.model_dump_json() for case in first_cases]
    assert first_json == [case.model_dump_json() for case in second_cases]
    assert first_summary == second_summary
    assert first_json != [case.model_dump_json() for case in other_cases]
    assert first_summary.seed != other_summary.seed


def test_dataset_counts_ids_timestamps_and_ground_truth_references(generated) -> None:
    cases, summary = generated
    assert (
        summary.scenario_count,
        summary.case_count,
        summary.suspicious_case_count,
        summary.benign_case_count,
    ) == (12, 36, 24, 12)

    all_ids: list[str] = []
    for case in cases:
        relevant = set(case.ground_truth.relevant_event_ids)
        role_ids = {
            event_id
            for identifiers in case.ground_truth.event_roles.values()
            for event_id in identifiers
        }
        assert 20 <= case.metadata.noise_event_count <= 80
        assert 3 <= case.metadata.relevant_event_count <= 10
        assert case.metadata.noise_event_count + case.metadata.relevant_event_count == len(
            case.events
        )
        assert [event.timestamp for event in case.events] == sorted(
            event.timestamp for event in case.events
        )
        assert all(event.timestamp.utcoffset() is not None for event in case.events)
        assert role_ids <= relevant <= {event.event_id for event in case.events}
        all_ids.extend(event.event_id for event in case.events)
    assert len(all_ids) == len(set(all_ids)) == summary.total_events


def test_noise_is_interleaved_and_benign_controls_are_unlabeled(generated) -> None:
    cases, _ = generated
    for case in cases:
        relevant_times = [
            event.timestamp
            for event in case.events
            if event.event_id in case.ground_truth.relevant_event_ids
        ]
        noise_times = [
            event.timestamp
            for event in case.events
            if event.event_id not in case.ground_truth.relevant_event_ids
        ]
        assert any(
            min(relevant_times) < timestamp < max(relevant_times) for timestamp in noise_times
        )

    for case in (case for case in cases if case.scenario_id.startswith("B")):
        assert case.ground_truth.suspicious is False
        expected_rules = ["R003"] if case.scenario_id == "B02" else []
        assert case.ground_truth.expected_rule_ids == expected_rules
        assert case.ground_truth.expected_mitre == []
        assert all("suspicious_sequence" not in event.ground_truth_labels for event in case.events)


def test_indicators_and_commands_are_safe(generated) -> None:
    cases, _ = generated
    validate_safe_dataset(cases)
    for event in (event for case in cases for event in case.events):
        for value in (event.src_ip, event.dst_ip):
            if value:
                assert any(ipaddress.ip_address(value) in network for network in SAFE_NETWORKS)
        if event.dst_domain:
            assert event.dst_domain.endswith((".example.com", ".example.net", ".example.org"))
        assert "http" not in (event.command_line or "").casefold()


def test_edge_case_metadata_matches_simulated_input(generated) -> None:
    cases, _ = generated
    for case in cases:
        canonical_ids = [event.event_id for event in case.events]
        if case.variant_id == "V02":
            assert "out_of_order_input" in case.metadata.edge_cases
            assert case.metadata.input_event_ids != canonical_ids
            assert set(case.metadata.input_event_ids) == set(canonical_ids)
        if case.variant_id == "V03":
            assert set(
                [
                    "duplicate_event",
                    "missing_event_input",
                    "multiple_users_same_host",
                    "simultaneous_processes",
                ]
            ) <= set(case.metadata.edge_cases)
            assert len(case.metadata.missing_event_ids) == 1
            assert set(case.metadata.input_event_ids).isdisjoint(case.metadata.missing_event_ids)
            duplicates = [event for event in case.events if event.raw.get("synthetic_duplicate")]
            assert len(duplicates) == 1
            assert duplicates[0].raw["duplicate_of_event_id"] in canonical_ids
            assert len({event.user for event in case.events if event.user}) > 1
            process_times = [
                event.timestamp
                for event in case.events
                if event.event_type == EventType.PROCESS_CREATE
            ]
            assert len(process_times) != len(set(process_times))


def test_s02_failures_precede_success_for_same_identity_within_five_minutes(generated) -> None:
    cases, _ = generated
    for variant in ("V01", "V02", "V03"):
        case = _case(cases, "S02", variant)
        role_map = case.ground_truth.event_roles
        by_id = {event.event_id: event for event in case.events}
        failures = [by_id[event_id] for event_id in role_map["failed_logon"]]
        success = by_id[role_map["successful_logon"][0]]
        assert len(failures) >= 5
        assert max(event.timestamp for event in failures) < success.timestamp
        assert success.timestamp - min(event.timestamp for event in failures) <= timedelta(
            minutes=5
        )
        assert {(event.host, event.user, event.src_ip) for event in [*failures, success]} == {
            (success.host, success.user, success.src_ip)
        }


def test_s05_causal_chain_uses_one_process(generated) -> None:
    cases, _ = generated
    case = _case(cases, "S05")
    by_id = {event.event_id: event for event in case.events}
    role_map = case.ground_truth.event_roles
    sequence = [
        by_id[role_map[role][0]]
        for role in ("powershell_process", "dns_query", "network_connection", "file_create")
    ]
    assert [event.timestamp for event in sequence] == sorted(event.timestamp for event in sequence)
    assert {event.process_id for event in sequence} == {sequence[0].process_id}


def test_b02_is_approved_benign_powershell_context(generated) -> None:
    cases, _ = generated
    case = _case(cases, "B02")
    event_id = case.ground_truth.event_roles["admin_powershell"][0]
    powershell = next(event for event in case.events if event.event_id == event_id)
    assert case.ground_truth.suspicious is False
    assert powershell.parent_process_name == "management-agent.exe"
    assert "approved-maintenance" in (powershell.command_line or "")


def test_write_and_load_are_idempotent(generated, tmp_path: Path) -> None:
    cases, summary = generated
    output = tmp_path / "incidents.jsonl"
    summary_output = tmp_path / "summary.json"
    assert write_dataset(cases, summary, output_path=output, summary_path=summary_output) == (
        True,
        True,
    )
    first_bytes = output.read_bytes()
    assert write_dataset(cases, summary, output_path=output, summary_path=summary_output) == (
        False,
        False,
    )
    assert output.read_bytes() == first_bytes
    assert load_dataset(output) == cases

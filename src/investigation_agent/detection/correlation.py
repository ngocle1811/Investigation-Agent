"""Reusable deterministic event correlation primitives."""

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import timedelta
from typing import Any

from investigation_agent.events.schemas import SecurityEvent

EventKey = tuple[Any, ...]


def normalize_process_name(value: str | None) -> str:
    """Normalize Windows image paths and case for stable process comparisons."""

    if not value:
        return ""
    return value.replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def sort_events_by_timestamp(events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
    """Canonicalize arbitrary input order without changing source event IDs."""

    return sorted(events, key=lambda event: (event.timestamp, event.event_id))


def stable_event_fingerprint(event: SecurityEvent) -> str:
    """Hash semantic event content while ignoring IDs and duplicate annotations."""

    payload = event.model_dump(mode="json", exclude={"event_id", "ground_truth_labels"})
    raw = dict(payload.get("raw") or {})
    raw.pop("synthetic_duplicate", None)
    raw.pop("duplicate_of_event_id", None)
    payload["raw"] = raw
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def deduplicate_events(events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
    """Remove repeated IDs and stable-content duplicates after canonical sorting."""

    unique: list[SecurityEvent] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    for event in sort_events_by_timestamp(events):
        fingerprint = stable_event_fingerprint(event)
        if event.event_id in seen_ids or fingerprint in seen_fingerprints:
            continue
        seen_ids.add(event.event_id)
        seen_fingerprints.add(fingerprint)
        unique.append(event)
    return unique


def group_by_entity(
    events: Iterable[SecurityEvent],
    *fields: str,
    require_all: bool = True,
) -> dict[EventKey, list[SecurityEvent]]:
    """Group events by named normalized fields using stable group/event ordering."""

    groups: defaultdict[EventKey, list[SecurityEvent]] = defaultdict(list)
    for event in sort_events_by_timestamp(events):
        key = tuple(getattr(event, field) for field in fields)
        if require_all and any(value is None for value in key):
            continue
        groups[key].append(event)
    return dict(sorted(groups.items(), key=lambda item: repr(item[0])))


def events_within_window(
    events: Iterable[SecurityEvent],
    *,
    start_time,
    window_seconds: int,
) -> list[SecurityEvent]:
    """Return events at or after ``start_time`` within an inclusive time window."""

    end_time = start_time + timedelta(seconds=window_seconds)
    return [
        event
        for event in sort_events_by_timestamp(events)
        if start_time <= event.timestamp <= end_time
    ]


def same_entities(
    left: SecurityEvent,
    right: SecurityEvent,
    fields: Sequence[str],
) -> bool:
    """Require non-null equality across every requested correlation key."""

    return all(
        getattr(left, field) is not None and getattr(left, field) == getattr(right, field)
        for field in fields
    )


def find_followed_by(
    first_events: Iterable[SecurityEvent],
    later_events: Iterable[SecurityEvent],
    *,
    same_fields: Sequence[str],
    window_seconds: int,
    predicate: Callable[[SecurityEvent, SecurityEvent], bool] | None = None,
) -> list[tuple[SecurityEvent, SecurityEvent]]:
    """Find canonical first→later pairs sharing configured entity keys."""

    pairs: list[tuple[SecurityEvent, SecurityEvent]] = []
    later_sorted = sort_events_by_timestamp(later_events)
    for first in sort_events_by_timestamp(first_events):
        for later in later_sorted:
            delta = (later.timestamp - first.timestamp).total_seconds()
            if delta < 0:
                continue
            if delta > window_seconds:
                break
            if not same_entities(first, later, same_fields):
                continue
            if predicate and not predicate(first, later):
                continue
            pairs.append((first, later))
    return pairs


def match_parent_child(parent: SecurityEvent, child: SecurityEvent) -> bool:
    """Validate a parent-child process relation from host, image, and process IDs."""

    return bool(
        parent.host
        and parent.host == child.host
        and parent.process_id
        and parent.process_id == child.parent_process_id
        and normalize_process_name(parent.process_name)
        == normalize_process_name(child.parent_process_name)
    )


def match_same_process(left: SecurityEvent, right: SecurityEvent) -> bool:
    """Match telemetry using the strongest normalized process correlation key."""

    return bool(
        left.host
        and left.host == right.host
        and left.process_id
        and left.process_id == right.process_id
    )

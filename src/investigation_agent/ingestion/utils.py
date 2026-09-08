"""Deterministic hashing and atomic serialization helpers."""

import hashlib
import json
from pathlib import Path
from typing import Any


def normalize_text(value: str) -> str:
    """Normalize newlines and trailing whitespace without changing semantics."""

    lines = (line.rstrip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
    return "\n".join(lines).strip()


def sha256_text(value: str) -> str:
    """Hash normalized UTF-8 text."""

    return hashlib.sha256(normalize_text(value).encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Hash source bytes exactly as downloaded."""

    return hashlib.sha256(value).hexdigest()


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Replace a file atomically after writing it beside the target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write stable, human-readable UTF-8 JSON atomically."""

    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    atomic_write_bytes(path, data + b"\n")

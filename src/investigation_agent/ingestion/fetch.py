"""Curated HTTP download and immutable raw-artifact storage."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from investigation_agent.ingestion.schemas import RawArtifact, SourceEntry
from investigation_agent.ingestion.utils import atomic_write_bytes, atomic_write_json, sha256_bytes

USER_AGENT = "investigation-agent/0.1 security-knowledge-ingestion"


class RawStore:
    """Download allowlisted sources and preserve raw bytes with sidecar metadata."""

    def __init__(self, root: Path, client: httpx.Client | None = None) -> None:
        self.root = root
        self.client = client or httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(120),
            headers={"User-Agent": USER_AGENT},
        )
        self._owns_client = client is None

    def close(self) -> None:
        """Close an internally-created HTTP client."""

        if self._owns_client:
            self.client.close()

    def __enter__(self) -> "RawStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def fetch(
        self,
        entry: SourceEntry,
        *,
        source: str,
        directory: str,
        refresh: bool = False,
        offline: bool = False,
    ) -> RawArtifact:
        """Return a cached artifact or download it, preserving timestamps when unchanged."""

        path = self.root / directory / entry.raw_filename
        metadata_path = path.with_name(f"{path.name}.metadata.json")
        cached = self._load_cached(metadata_path, path)
        if cached and not refresh:
            return cached
        if offline:
            if cached:
                return cached
            raise FileNotFoundError(f"No cached raw artifact for {entry.id}")

        response = self.client.get(entry.url)
        response.raise_for_status()
        content = response.content
        content_hash = sha256_bytes(content)
        if cached and cached.content_hash == content_hash:
            return cached

        artifact = RawArtifact(
            source=source,
            source_type=entry.source_type,
            url=str(response.url),
            path=path,
            downloaded_at=datetime.now(UTC),
            content_hash=content_hash,
            version=entry.version,
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
        )
        atomic_write_bytes(path, content)
        atomic_write_json(metadata_path, artifact.model_dump(mode="json"))
        return artifact

    @staticmethod
    def _load_cached(metadata_path: Path, raw_path: Path) -> RawArtifact | None:
        """Load a sidecar only when it still describes the current raw bytes."""

        if not metadata_path.exists() or not raw_path.exists():
            return None
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            payload["path"] = raw_path
            artifact = RawArtifact.model_validate(payload)
        except (json.JSONDecodeError, OSError, ValueError):
            return None
        if sha256_bytes(raw_path.read_bytes()) != artifact.content_hash:
            return None
        return artifact

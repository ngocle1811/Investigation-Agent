"""Qdrant client and connectivity helpers."""

from functools import lru_cache

from qdrant_client import QdrantClient

from investigation_agent.common.config import get_settings


@lru_cache
def get_qdrant_client() -> QdrantClient:
    """Create a reusable Qdrant client from environment-backed settings."""

    settings = get_settings()
    api_key = settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None
    return QdrantClient(url=settings.resolved_qdrant_url, api_key=api_key, timeout=5)


def check_qdrant() -> tuple[bool, str]:
    """Check Qdrant connectivity by listing collections."""

    try:
        get_qdrant_client().get_collections()
        return True, "ok"
    except Exception as exc:  # pragma: no cover - integration smoke tests cover this path
        return False, exc.__class__.__name__

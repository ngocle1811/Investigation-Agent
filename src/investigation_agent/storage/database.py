"""PostgreSQL engine and connectivity helpers."""

from functools import lru_cache

from sqlalchemy import Engine, create_engine, text

from investigation_agent.common.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """Create a pooled SQLAlchemy engine without opening an eager connection."""

    return create_engine(get_settings().sqlalchemy_url, pool_pre_ping=True)


def check_database() -> tuple[bool, str]:
    """Check PostgreSQL connectivity with a minimal query."""

    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # pragma: no cover - integration smoke tests cover this path
        return False, exc.__class__.__name__

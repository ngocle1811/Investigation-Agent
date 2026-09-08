"""Configuration behavior tests."""

from pydantic import SecretStr

from investigation_agent.common.config import Settings


def test_database_url_is_built_from_components() -> None:
    """Credentials are URL encoded when composing a connection string."""

    settings = Settings(
        _env_file=None,
        postgres_user="analyst@example",
        postgres_password=SecretStr("pass word"),
        postgres_host="db",
        postgres_port=5433,
        postgres_db="cases",
    )
    assert settings.sqlalchemy_url == (
        "postgresql+psycopg://analyst%40example:pass+word@db:5433/cases"
    )


def test_explicit_urls_take_precedence() -> None:
    """Single explicit service URLs override component settings."""

    settings = Settings(
        _env_file=None,
        database_url="sqlite+pysqlite:///:memory:",
        qdrant_url="http://vector:6333",
    )
    assert settings.sqlalchemy_url == "sqlite+pysqlite:///:memory:"
    assert settings.resolved_qdrant_url == "http://vector:6333"

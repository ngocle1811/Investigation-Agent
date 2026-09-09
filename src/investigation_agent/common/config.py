"""Environment-backed application configuration."""

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and an optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    app_name: str = "Investigation Agent"
    app_env: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    backend_url: str = "http://localhost:8000"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "investigation_agent"
    postgres_user: str = "investigation"
    postgres_password: SecretStr = Field(default=SecretStr("investigation-local"))
    database_url: str | None = None

    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_url: str | None = None
    qdrant_api_key: SecretStr | None = None
    qdrant_collection: str = "security_knowledge"

    embedding_provider: str = "fastembed"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_batch_size: int = 32
    llm_provider: str = "mock"
    llm_model: str = "mock-investigator-v1"
    llm_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    gemini_thinking_level: str | None = None
    llm_base_url: str | None = None
    llm_timeout_seconds: float = Field(default=60.0, gt=0)
    llm_max_output_tokens: int = Field(default=3000, ge=256)
    investigation_retrieval_top_k: int = Field(default=5, ge=1, le=20)
    judge_model: str = "mock-judge-v1"
    random_seed: int = 42
    project_root: Path = Field(default_factory=lambda: Path.cwd())

    @property
    def sqlalchemy_url(self) -> str:
        """Return an explicit URL or build a PostgreSQL URL from individual settings."""

        if self.database_url:
            return self.database_url
        password = quote_plus(self.postgres_password.get_secret_value())
        user = quote_plus(self.postgres_user)
        return (
            f"postgresql+psycopg://{user}:{password}@{self.postgres_host}:"
            f"{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def resolved_qdrant_url(self) -> str:
        """Return the configured Qdrant HTTP endpoint."""

        return self.qdrant_url or f"http://{self.qdrant_host}:{self.qdrant_port}"

    @property
    def embedding_cache_dir(self) -> Path:
        """Return the project-local cache for downloaded embedding model files."""

        return self.project_root.resolve() / "data" / "models" / "fastembed"

    @property
    def resolved_llm_api_key(self) -> SecretStr | None:
        """Prefer Gemini's conventional variable for Gemini, with generic fallback."""

        if self.llm_provider.casefold() == "gemini" and self.gemini_api_key is not None:
            if self.gemini_api_key.get_secret_value().strip():
                return self.gemini_api_key
        return self.llm_api_key


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()

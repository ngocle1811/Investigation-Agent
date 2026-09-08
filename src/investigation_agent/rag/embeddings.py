"""Embedding provider abstraction with local and deterministic implementations."""

import hashlib
import math
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class EmbeddingProvider(ABC):
    """Small provider contract shared by indexing and query-time retrieval."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the provider-specific model identifier."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Return vector dimensionality after provider initialization."""

    @abstractmethod
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed document texts in input order."""

    def embed_query(self, text: str) -> list[float]:
        """Embed one query using the same model and normalization path."""

        return self.embed_documents([text])[0]


class FastEmbedProvider(EmbeddingProvider):
    """CPU-friendly local embeddings powered by Qdrant FastEmbed."""

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        *,
        cache_dir: Path | None = None,
        batch_size: int = 32,
        model: Any | None = None,
    ) -> None:
        self._model_name = model_name
        self._batch_size = batch_size
        self._dimension: int | None = None
        if model is None:
            try:
                from fastembed import TextEmbedding
            except ImportError as exc:  # pragma: no cover - dependency wiring guard
                raise RuntimeError("FastEmbed is not installed; run pip install -e .") from exc
            kwargs: dict[str, Any] = {"model_name": model_name}
            if cache_dir is not None:
                kwargs["cache_dir"] = str(cache_dir)
            model = TextEmbedding(**kwargs)
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimension(self) -> int:
        if self._dimension is None:
            raise RuntimeError("Embedding dimension is available after the first embedding call")
        return self._dimension

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = [
            [float(value) for value in vector]
            for vector in self._model.embed(texts, batch_size=self._batch_size)
        ]
        if len(vectors) != len(texts):
            raise RuntimeError("Embedding provider returned a different number of vectors")
        dimensions = {len(vector) for vector in vectors}
        if len(dimensions) != 1 or 0 in dimensions:
            raise RuntimeError("Embedding provider returned inconsistent vector dimensions")
        dimension = dimensions.pop()
        if self._dimension is not None and self._dimension != dimension:
            raise RuntimeError("Embedding vector dimension changed during this process")
        self._dimension = dimension
        return vectors


class HashEmbeddingProvider(EmbeddingProvider):
    """Deterministic dependency-free embeddings for tests and offline development."""

    def __init__(self, dimension: int = 128) -> None:
        if dimension < 8:
            raise ValueError("Hash embedding dimension must be at least 8")
        self._dimension = dimension

    @property
    def model_name(self) -> str:
        return f"hash-{self._dimension}"

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self._dimension
        for token in text.casefold().split():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self._dimension
            vector[index] += -1.0 if digest[4] & 1 else 1.0
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


def create_embedding_provider(
    provider: str,
    *,
    model_name: str,
    cache_dir: Path | None = None,
    batch_size: int = 32,
) -> EmbeddingProvider:
    """Build a configured embedding provider without leaking model dimensions."""

    normalized = provider.casefold()
    if normalized in {"fastembed", "local"}:
        return FastEmbedProvider(
            model_name=model_name,
            cache_dir=cache_dir,
            batch_size=batch_size,
        )
    if normalized == "hash":
        return HashEmbeddingProvider()
    raise ValueError(f"Unsupported embedding provider: {provider}")

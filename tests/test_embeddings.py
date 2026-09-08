"""Embedding provider contract tests without downloading a model."""

import math

import pytest

from investigation_agent.rag.embeddings import FastEmbedProvider, HashEmbeddingProvider


class FakeFastEmbedModel:
    """Minimal stand-in matching FastEmbed's lazy generator API."""

    def embed(self, texts: list[str], *, batch_size: int):
        assert batch_size == 2
        for index, _text in enumerate(texts, 1):
            yield [float(index), 2.0, 3.0]


def test_fastembed_provider_discovers_dimension_and_preserves_order() -> None:
    provider = FastEmbedProvider(model_name="fake", batch_size=2, model=FakeFastEmbedModel())
    with pytest.raises(RuntimeError, match="after the first"):
        _ = provider.dimension
    assert provider.embed_documents(["first", "second"]) == [
        [1.0, 2.0, 3.0],
        [2.0, 2.0, 3.0],
    ]
    assert provider.dimension == 3


def test_hash_provider_is_deterministic_and_normalized() -> None:
    provider = HashEmbeddingProvider(dimension=32)
    first, second = provider.embed_documents(["failed logon 4625", "failed logon 4625"])
    assert first == second
    assert len(first) == provider.dimension
    assert math.isclose(math.sqrt(sum(value * value for value in first)), 1.0)

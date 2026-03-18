"""Tests for the Matryoshka embedding layer.

These tests run WITHOUT sentence-transformers installed, verifying
graceful degradation. The module must never crash when the optional
dependency is missing.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from src.embeddings import (
    EmbeddingIndex,
    SearchResult,
    TIER_DIMS,
    _truncate_float,
    _quantize_int8,
    _quantize_binary,
    _cosine_similarity,
    _cosine_similarity_int8,
    _hamming_similarity,
    _check_sentence_transformers,
)


class TestMatryoshkaTruncation:
    """Test the dimensionality reduction functions with synthetic vectors."""

    def _random_unit_vec(self, dim: int = 384) -> np.ndarray:
        rng = np.random.default_rng(42)
        v = rng.standard_normal(dim).astype(np.float32)
        v /= np.linalg.norm(v)
        return v

    def test_truncate_float_preserves_shape(self):
        vec = self._random_unit_vec()
        for dims in [256, 128, 64]:
            result = _truncate_float(vec, dims)
            assert result.shape == (dims,)
            assert result.dtype == np.float32

    def test_truncate_float_is_normalized(self):
        vec = self._random_unit_vec()
        result = _truncate_float(vec, 256)
        norm = np.linalg.norm(result)
        assert abs(norm - 1.0) < 1e-5

    def test_quantize_int8_shape_and_dtype(self):
        vec = self._random_unit_vec()
        result = _quantize_int8(vec, 128)
        assert result.shape == (128,)
        assert result.dtype == np.int8
        assert np.all(result >= -127) and np.all(result <= 127)

    def test_quantize_binary_shape(self):
        vec = self._random_unit_vec()
        result = _quantize_binary(vec, 64)
        # 64 bits = 8 bytes
        assert result.shape == (8,)
        assert result.dtype == np.uint8


class TestSimilarityFunctions:
    """Test similarity scoring with known vectors."""

    def test_cosine_identical_vectors(self):
        v = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        assert abs(_cosine_similarity(v, v) - 1.0) < 1e-5

    def test_cosine_orthogonal_vectors(self):
        a = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        b = np.array([0.0, 1.0, 0.0], dtype=np.float32)
        assert abs(_cosine_similarity(a, b)) < 1e-5

    def test_cosine_int8_similar(self):
        a = np.array([100, 50, -30], dtype=np.int8)
        b = np.array([100, 50, -30], dtype=np.int8)
        assert _cosine_similarity_int8(a, b) > 0.99

    def test_hamming_identical(self):
        a = np.array([0xFF, 0x00], dtype=np.uint8)
        assert abs(_hamming_similarity(a, a) - 1.0) < 1e-5

    def test_hamming_opposite(self):
        a = np.array([0xFF, 0xFF], dtype=np.uint8)
        b = np.array([0x00, 0x00], dtype=np.uint8)
        assert abs(_hamming_similarity(a, b)) < 1e-5


class TestEmbeddingIndexDegradation:
    """Test that EmbeddingIndex works when sentence-transformers is missing."""

    def test_add_returns_false_without_model(self, tmp_path):
        """add() returns False (not crash) when sentence-transformers missing."""
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        result = idx.add("/some/path.txt", "hello world", "hot")
        # If sentence-transformers is not installed, should return False
        if not _check_sentence_transformers():
            assert result is False
        # If installed, should return True
        else:
            assert result is True

    def test_search_returns_empty_without_model(self, tmp_path):
        """search() returns [] when sentence-transformers missing."""
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        results = idx.search("test query", top_k=5)
        if not _check_sentence_transformers():
            assert results == []

    def test_count_empty_index(self, tmp_path):
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        assert idx.count() == 0
        assert idx.count("hot") == 0

    def test_invalid_tier_raises(self, tmp_path):
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        with pytest.raises(ValueError, match="Unknown tier"):
            idx.add("/path", "text", "invalid_tier")


class TestEmbeddingIndexPersistence:
    """Test save/load round-trip with synthetic data (no model needed)."""

    def test_save_load_roundtrip(self, tmp_path):
        idx_dir = tmp_path / "idx"
        idx = EmbeddingIndex(index_dir=idx_dir)

        # Manually inject synthetic embeddings (bypass model)
        vec = np.random.default_rng(42).standard_normal(384).astype(np.float32)
        vec /= np.linalg.norm(vec)

        # Hot tier: 384-dim float32
        hot_vec = _truncate_float(vec, 384)
        idx._paths["hot"] = ["/a.txt"]
        idx._embeddings["hot"] = hot_vec.reshape(1, -1)
        idx._dirty.add("hot")

        # Cold tier: 128-dim int8
        cold_vec = _quantize_int8(vec, 128)
        idx._paths["cold"] = ["/b.txt"]
        idx._embeddings["cold"] = cold_vec.reshape(1, -1)
        idx._dirty.add("cold")

        # Frozen tier: 64-dim binary packed
        frozen_vec = _quantize_binary(vec, 64)
        idx._paths["frozen"] = ["/c.txt"]
        idx._embeddings["frozen"] = frozen_vec.reshape(1, -1)
        idx._dirty.add("frozen")

        idx.save()

        # Reload
        idx2 = EmbeddingIndex(index_dir=idx_dir)
        assert idx2._paths["hot"] == ["/a.txt"]
        assert idx2._paths["cold"] == ["/b.txt"]
        assert idx2._paths["frozen"] == ["/c.txt"]
        assert idx2._embeddings["hot"].shape == (1, 384)
        assert idx2._embeddings["cold"].shape == (1, 128)
        assert idx2._embeddings["frozen"].shape == (1, 8)  # 64 bits packed

    def test_remove_from_tier(self, tmp_path):
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        vec = np.ones(384, dtype=np.float32)
        vec /= np.linalg.norm(vec)

        idx._paths["hot"] = ["/a.txt", "/b.txt"]
        idx._embeddings["hot"] = np.vstack([
            _truncate_float(vec, 384).reshape(1, -1),
            _truncate_float(vec * -1, 384).reshape(1, -1),
        ])

        idx._remove_from_tier("/a.txt", "hot")
        assert idx._paths["hot"] == ["/b.txt"]
        assert idx._embeddings["hot"].shape == (1, 384)

    def test_remove_all_tiers(self, tmp_path):
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        vec = np.ones(384, dtype=np.float32)
        vec /= np.linalg.norm(vec)

        for tier, dims in TIER_DIMS.items():
            if tier == "frozen":
                t_vec = _quantize_binary(vec, dims)
            elif tier == "cold":
                t_vec = _quantize_int8(vec, dims)
            else:
                t_vec = _truncate_float(vec, dims)
            idx._paths[tier] = ["/a.txt"]
            idx._embeddings[tier] = t_vec.reshape(1, -1)

        idx.remove("/a.txt")
        assert idx.count() == 0

    def test_tiers_summary(self, tmp_path):
        idx = EmbeddingIndex(index_dir=tmp_path / "idx")
        summary = idx.tiers_summary()
        assert summary == {"hot": 0, "warm": 0, "cold": 0, "frozen": 0}


class TestContextIntegration:
    """Test that SemanticIndex creates embedding index without crashing."""

    def test_semantic_index_has_embedding_index(self, tmp_path):
        from src.context import SemanticIndex
        si = SemanticIndex(tmp_path)
        assert hasattr(si, "_embedding_index")
        assert isinstance(si._embedding_index, EmbeddingIndex)

    def test_index_artifact_does_not_crash(self, tmp_path):
        from src.context import SemanticIndex
        from src.metadata import ArtifactMeta
        si = SemanticIndex(tmp_path)
        meta = ArtifactMeta(path="/test.md", tier="hot", created_at=1.0, last_accessed=1.0)
        entry = si.index_artifact(Path("/test.md"), "Some test content", meta)
        assert entry.path == "/test.md"
        si.save(force=True)

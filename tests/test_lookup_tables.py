"""Tests for LSH index, Product Quantization codebook, and binary embeddings."""

import os
import tempfile

import numpy as np
import pytest

from src.lookup_tables import (
    LSHIndex,
    PQCodebook,
    binary_search,
    hamming_distance,
    to_binary,
)


DIM = 384
RNG = np.random.RandomState(42)


# ---------------------------------------------------------------------------
# Binary embedding utilities
# ---------------------------------------------------------------------------

class TestBinaryEmbeddings:
    def test_to_binary_single(self):
        emb = RNG.randn(DIM).astype(np.float32)
        b = to_binary(emb)
        assert b.dtype == np.uint8
        assert b.shape == (DIM // 8,)  # 384 / 8 = 48 bytes

    def test_to_binary_batch(self):
        embs = RNG.randn(10, DIM).astype(np.float32)
        b = to_binary(embs)
        assert b.shape == (10, DIM // 8)

    def test_hamming_distance_self(self):
        emb = RNG.randn(DIM).astype(np.float32)
        b = to_binary(emb)
        assert hamming_distance(b, b) == 0

    def test_hamming_distance_different(self):
        b1 = to_binary(RNG.randn(DIM).astype(np.float32))
        b2 = to_binary(RNG.randn(DIM).astype(np.float32))
        dist = hamming_distance(b1, b2)
        assert 0 < dist <= DIM

    def test_binary_search_finds_self(self):
        embs = RNG.randn(20, DIM).astype(np.float32)
        db = to_binary(embs)
        query = to_binary(embs[0])
        results = binary_search(query, db, top_k=5)
        assert len(results) == 5
        assert results[0][0] == 0  # closest is itself
        assert results[0][1] == 0  # zero distance

    def test_binary_search_empty_db(self):
        query = to_binary(RNG.randn(DIM).astype(np.float32))
        empty = np.array([]).reshape(0, DIM // 8)
        assert binary_search(query, empty, top_k=5) == []


# ---------------------------------------------------------------------------
# LSH Index
# ---------------------------------------------------------------------------

class TestLSHIndex:
    @pytest.fixture
    def populated_index(self):
        idx = LSHIndex(dim=DIM, n_hyperplanes=12, n_tables=4, seed=0)
        self._embeddings = {}
        rng = np.random.RandomState(0)
        for i in range(50):
            emb = rng.randn(DIM).astype(np.float32)
            self._embeddings[f"art-{i}"] = emb
            idx.add(f"art-{i}", emb)
        return idx

    def test_empty_search(self):
        idx = LSHIndex(dim=DIM)
        results = idx.search(RNG.randn(DIM).astype(np.float32), top_k=5)
        assert results == []

    def test_add_and_search(self, populated_index):
        # Query with art-0's embedding — it should appear in results
        query = self._embeddings["art-0"]
        results = populated_index.search(query, top_k=5)
        assert len(results) > 0
        ids = [r[0] for r in results]
        assert "art-0" in ids
        # Similarity to self should be ~1.0
        art0_sim = dict(results).get("art-0", 0.0)
        assert art0_sim > 0.99

    def test_search_returns_similarities(self, populated_index):
        query = self._embeddings["art-5"]
        results = populated_index.search(query, top_k=3)
        for _aid, sim in results:
            assert -1.0 <= sim <= 1.0

    def test_save_load_roundtrip(self, populated_index):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "lsh.npz")
            populated_index.save(path)
            loaded = LSHIndex.load(path)

            query = self._embeddings["art-0"]
            r1 = populated_index.search(query, top_k=5)
            r2 = loaded.search(query, top_k=5)
            assert len(r1) == len(r2)
            assert r1[0][0] == r2[0][0]

    def test_save_empty_index(self):
        idx = LSHIndex(dim=DIM)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "lsh-empty.npz")
            idx.save(path)
            loaded = LSHIndex.load(path)
            assert loaded.search(RNG.randn(DIM).astype(np.float32)) == []

    def test_zero_query(self, populated_index):
        results = populated_index.search(np.zeros(DIM), top_k=5)
        assert results == []


# ---------------------------------------------------------------------------
# Product Quantization
# ---------------------------------------------------------------------------

class TestPQCodebook:
    @pytest.fixture
    def trained_pq(self):
        pq = PQCodebook(dim=DIM, m=8, k=256)
        rng = np.random.RandomState(99)
        data = rng.randn(500, DIM).astype(np.float32)
        pq.train(data)
        return pq, data

    def test_untrained_encode_raises(self):
        pq = PQCodebook(dim=DIM)
        with pytest.raises(RuntimeError, match="not trained"):
            pq.encode(RNG.randn(DIM).astype(np.float32))

    def test_untrained_decode_raises(self):
        pq = PQCodebook(dim=DIM)
        with pytest.raises(RuntimeError, match="not trained"):
            pq.decode(np.zeros(8, dtype=np.uint8))

    def test_dim_not_divisible(self):
        with pytest.raises(ValueError, match="divisible"):
            PQCodebook(dim=385, m=8)

    def test_k_too_large(self):
        with pytest.raises(ValueError, match="<= 256"):
            PQCodebook(dim=DIM, k=257)

    def test_train_too_few_vectors(self):
        pq = PQCodebook(dim=DIM, m=8, k=256)
        with pytest.raises(ValueError, match="at least 256"):
            pq.train(RNG.randn(100, DIM).astype(np.float32))

    def test_encode_single(self, trained_pq):
        pq, data = trained_pq
        codes = pq.encode(data[0])
        assert codes.shape == (8,)
        assert codes.dtype == np.uint8

    def test_encode_batch(self, trained_pq):
        pq, data = trained_pq
        codes = pq.encode(data[:10])
        assert codes.shape == (10, 8)
        assert codes.dtype == np.uint8

    def test_decode_roundtrip(self, trained_pq):
        pq, data = trained_pq
        original = data[0]
        codes = pq.encode(original)
        reconstructed = pq.decode(codes)
        assert reconstructed.shape == (DIM,)
        # Relative reconstruction error should be reasonable (< 1.0)
        error = np.linalg.norm(original - reconstructed) / np.linalg.norm(original)
        assert error < 1.0

    def test_search_finds_self(self, trained_pq):
        pq, data = trained_pq
        all_codes = pq.encode(data)
        results = pq.search(data[0], all_codes, top_k=5)
        assert len(results) == 5
        assert results[0][0] == 0  # should find itself first
        assert results[0][1] < 1e-4  # near-zero distance

    def test_search_empty_codes(self, trained_pq):
        pq, _ = trained_pq
        empty = np.array([], dtype=np.uint8).reshape(0, 8)
        assert pq.search(RNG.randn(DIM).astype(np.float32), empty, top_k=5) == []

    def test_save_load_roundtrip(self, trained_pq):
        pq, data = trained_pq
        codes_before = pq.encode(data[0])
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "pq.npz")
            pq.save(path)
            loaded = PQCodebook.load(path)
            codes_after = loaded.encode(data[0])
            assert np.array_equal(codes_before, codes_after)

    def test_save_untrained_raises(self):
        pq = PQCodebook(dim=DIM)
        with pytest.raises(RuntimeError, match="not trained"):
            pq.save("/tmp/should-not-exist.npz")

    def test_is_trained_property(self, trained_pq):
        pq, _ = trained_pq
        assert pq.is_trained is True
        fresh = PQCodebook(dim=DIM)
        assert fresh.is_trained is False

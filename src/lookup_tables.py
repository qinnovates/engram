"""
Lookup tables for fast embedding retrieval and compression.

Two structures for different tiers of the memory hierarchy:

1. LSH (Locality-Sensitive Hashing) — O(1) approximate nearest neighbor retrieval.
   Uses random hyperplane LSH: hash each embedding by the sign of its dot product
   with random projection vectors. Multiple hash tables improve recall at the cost
   of memory (same tradeoff as Bloom filters with multiple hash functions).

2. Product Quantization (PQ) — lossy embedding compression for frozen-tier storage.
   Splits each embedding into M sub-vectors, quantizes each to the nearest centroid
   from a trained codebook. Reduces a 384-dim float32 embedding (1536 bytes) to
   8 uint8 codes (8 bytes) — 192x compression. Asymmetric distance computation
   preserves retrieval quality better than symmetric.

3. Binary embeddings — sign-based binarization with Hamming distance.
   Fastest possible similarity search at the cost of precision.
   384-dim float32 (1536 bytes) -> 48 bytes packed bits.

All structures are pure numpy/scipy with no FAISS dependency.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import numpy as np


# ---------------------------------------------------------------------------
# Binary embedding utilities
# ---------------------------------------------------------------------------

def to_binary(embedding: np.ndarray) -> np.ndarray:
    """Sign-based binarization + packbits.

    Converts a float embedding to a compact binary representation where each
    dimension becomes a single bit (1 if positive, 0 if negative/zero).

    Args:
        embedding: Float embedding vector or batch of vectors.
                   Shape (d,) for single or (n, d) for batch.

    Returns:
        Packed bit array. Shape (ceil(d/8),) or (n, ceil(d/8)).
    """
    bits = (embedding > 0).astype(np.uint8)
    if bits.ndim == 1:
        return np.packbits(bits)
    return np.packbits(bits, axis=1)


def hamming_distance(a: np.ndarray, b: np.ndarray) -> int:
    """Popcount-based Hamming distance between two packed bit arrays.

    Args:
        a: Packed bit array from to_binary().
        b: Packed bit array from to_binary().

    Returns:
        Number of differing bits.
    """
    xor = np.bitwise_xor(a, b)
    # Popcount via lookup: unpack and sum
    return int(np.unpackbits(xor).sum())


def binary_search(
    query: np.ndarray,
    database: np.ndarray,
    top_k: int = 5,
) -> list[tuple[int, int]]:
    """Fast Hamming-distance search over packed binary embeddings.

    Args:
        query: Single packed binary embedding, shape (b,).
        database: Matrix of packed binary embeddings, shape (n, b).
        top_k: Number of nearest neighbors to return.

    Returns:
        List of (index, hamming_distance) tuples, sorted ascending by distance.
    """
    if database.ndim < 2 or len(database) == 0:
        return []
    # Vectorized XOR + popcount
    xor = np.bitwise_xor(database, query[np.newaxis, :])
    # Unpack each row and sum bits — vectorized popcount
    distances = np.array([int(np.unpackbits(row).sum()) for row in xor])
    k = min(top_k, len(distances))
    indices = np.argpartition(distances, k)[:k]
    indices = indices[np.argsort(distances[indices])]
    return [(int(idx), int(distances[idx])) for idx in indices]


# ---------------------------------------------------------------------------
# LSH Index — random hyperplane locality-sensitive hashing
# ---------------------------------------------------------------------------

class LSHIndex:
    """Locality-sensitive hashing index for O(1) approximate nearest neighbor.

    Uses random hyperplane LSH: each hyperplane divides the embedding space
    in half. The hash of a vector is the concatenation of signs of its dot
    products with all hyperplanes, giving a bucket address.

    Multiple independent hash tables (each with its own random hyperplanes)
    improve recall — a match in ANY table is a candidate.

    Parameters:
        dim: Embedding dimensionality.
        n_hyperplanes: Number of hyperplanes per table (hash bits).
                       12 hyperplanes = 2^12 = 4096 buckets per table.
        n_tables: Number of independent hash tables.
        seed: Random seed for reproducible hyperplane generation.
    """

    def __init__(
        self,
        dim: int,
        n_hyperplanes: int = 12,
        n_tables: int = 4,
        seed: int = 42,
    ):
        self.dim = dim
        self.n_hyperplanes = n_hyperplanes
        self.n_tables = n_tables
        self.seed = seed

        rng = np.random.RandomState(seed)
        # Shape: (n_tables, n_hyperplanes, dim)
        self.hyperplanes = rng.randn(n_tables, n_hyperplanes, dim).astype(np.float32)

        # Each table is a dict mapping hash -> list of (artifact_id, embedding)
        self.tables: list[dict[int, list[tuple[str, np.ndarray]]]] = [
            {} for _ in range(n_tables)
        ]

    def _hash(self, embedding: np.ndarray, table_idx: int) -> int:
        """Compute the hash bucket for an embedding in a specific table."""
        projections = self.hyperplanes[table_idx] @ embedding  # (n_hyperplanes,)
        bits = (projections > 0).astype(np.int32)
        # Convert bit array to integer hash
        hash_val = 0
        for bit in bits:
            hash_val = (hash_val << 1) | int(bit)
        return hash_val

    def add(self, artifact_id: str, embedding: np.ndarray) -> None:
        """Hash and store an embedding in all tables.

        Args:
            artifact_id: Unique identifier for the artifact.
            embedding: Float embedding vector, shape (dim,).
        """
        embedding = embedding.astype(np.float32).ravel()
        for t in range(self.n_tables):
            h = self._hash(embedding, t)
            bucket = self.tables[t].setdefault(h, [])
            bucket.append((artifact_id, embedding))

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ) -> list[tuple[str, float]]:
        """Find approximate nearest neighbors via LSH lookup.

        Hashes the query into each table, collects all candidates from
        matching buckets, deduplicates, and ranks by cosine similarity.

        Args:
            query_embedding: Query vector, shape (dim,).
            top_k: Number of results to return.

        Returns:
            List of (artifact_id, cosine_similarity) tuples, descending.
        """
        query = query_embedding.astype(np.float32).ravel()
        query_norm = np.linalg.norm(query)
        if query_norm == 0:
            return []

        # Collect candidates from all tables (deduplicate by id)
        candidates: dict[str, np.ndarray] = {}
        for t in range(self.n_tables):
            h = self._hash(query, t)
            for artifact_id, emb in self.tables[t].get(h, []):
                if artifact_id not in candidates:
                    candidates[artifact_id] = emb

        if not candidates:
            return []

        # Rank by cosine similarity
        results: list[tuple[str, float]] = []
        for artifact_id, emb in candidates.items():
            emb_norm = np.linalg.norm(emb)
            if emb_norm == 0:
                continue
            sim = float(np.dot(query, emb) / (query_norm * emb_norm))
            results.append((artifact_id, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def save(self, path: Optional[str] = None) -> Path:
        """Persist the LSH index to disk.

        Saves hyperplanes and all bucket contents. The bucket structure
        is serialized as parallel arrays of ids, embeddings, table indices,
        and hashes.

        Args:
            path: File path. Defaults to ~/.engram/index/lsh-tables.npz.

        Returns:
            Path where the index was saved.
        """
        if path is None:
            path = os.path.join(os.path.expanduser("~"), ".engram", "index", "lsh-tables.npz")

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # Flatten bucket contents into parallel arrays
        all_ids: list[str] = []
        all_embeddings: list[np.ndarray] = []
        all_table_indices: list[int] = []
        all_hashes: list[int] = []

        for t in range(self.n_tables):
            for h, entries in self.tables[t].items():
                for artifact_id, emb in entries:
                    all_ids.append(artifact_id)
                    all_embeddings.append(emb)
                    all_table_indices.append(t)
                    all_hashes.append(h)

        save_kwargs: dict = {
            "hyperplanes": self.hyperplanes,
            "config": np.array([self.dim, self.n_hyperplanes, self.n_tables, self.seed]),
        }
        if all_ids:
            save_kwargs["ids"] = np.array(all_ids)
            save_kwargs["embeddings"] = np.array(all_embeddings)
            save_kwargs["table_indices"] = np.array(all_table_indices)
            save_kwargs["hashes"] = np.array(all_hashes)

        np.savez(str(save_path), **save_kwargs)
        return save_path

    @classmethod
    def load(cls, path: Optional[str] = None) -> "LSHIndex":
        """Load an LSH index from disk.

        Args:
            path: File path. Defaults to ~/.engram/index/lsh-tables.npz.

        Returns:
            Populated LSHIndex instance.
        """
        if path is None:
            path = os.path.join(os.path.expanduser("~"), ".engram", "index", "lsh-tables.npz")

        data = np.load(path, allow_pickle=True)
        config = data["config"]
        dim, n_hyperplanes, n_tables, seed = int(config[0]), int(config[1]), int(config[2]), int(config[3])

        index = cls(dim=dim, n_hyperplanes=n_hyperplanes, n_tables=n_tables, seed=seed)
        # Overwrite hyperplanes with saved ones (same seed should match, but be safe)
        index.hyperplanes = data["hyperplanes"]

        # Rebuild tables from saved entries
        if "ids" in data:
            ids = data["ids"]
            embeddings = data["embeddings"]
            table_indices = data["table_indices"]
            hashes = data["hashes"]

            for i in range(len(ids)):
                t = int(table_indices[i])
                h = int(hashes[i])
                bucket = index.tables[t].setdefault(h, [])
                bucket.append((str(ids[i]), embeddings[i].astype(np.float32)))

        return index


# ---------------------------------------------------------------------------
# Product Quantization codebook
# ---------------------------------------------------------------------------

class PQCodebook:
    """Product Quantization for embedding compression.

    Splits each embedding vector into M sub-vectors and quantizes each
    sub-vector to one of K centroids. This reduces storage from
    dim * 4 bytes (float32) to M bytes (uint8 indices).

    For a 384-dim embedding: 1536 bytes -> 8 bytes (192x compression).

    Asymmetric distance computation (ADC) preserves retrieval quality:
    the query is NOT quantized, only the database vectors are. Distance
    is computed between exact query sub-vectors and centroid sub-vectors.

    Parameters:
        dim: Embedding dimensionality.
        m: Number of sub-vector partitions. dim must be divisible by m.
        k: Number of centroids per sub-quantizer (max 256 for uint8).
    """

    def __init__(self, dim: int = 384, m: int = 8, k: int = 256):
        if dim % m != 0:
            raise ValueError(f"dim ({dim}) must be divisible by m ({m})")
        if k > 256:
            raise ValueError(f"k ({k}) must be <= 256 for uint8 encoding")

        self.dim = dim
        self.m = m
        self.k = k
        self.sub_dim = dim // m
        # Centroids shape: (m, k, sub_dim) — None until trained
        self.centroids: Optional[np.ndarray] = None
        self._trained = False

    @property
    def is_trained(self) -> bool:
        return self._trained

    def train(self, embeddings: np.ndarray, max_iter: int = 20) -> None:
        """Train the codebook centroids using k-means on each sub-vector space.

        Args:
            embeddings: Training data, shape (n, dim).
            max_iter: Maximum k-means iterations per sub-quantizer.
        """
        from scipy.cluster.vq import kmeans2

        n = embeddings.shape[0]
        if n < self.k:
            raise ValueError(
                f"Need at least {self.k} training vectors, got {n}"
            )

        embeddings = embeddings.astype(np.float32)
        self.centroids = np.zeros((self.m, self.k, self.sub_dim), dtype=np.float32)

        for i in range(self.m):
            sub = embeddings[:, i * self.sub_dim : (i + 1) * self.sub_dim]
            centroids, _labels = kmeans2(
                sub, self.k, iter=max_iter, minit="points"
            )
            self.centroids[i] = centroids

        self._trained = True

    def encode(self, embedding: np.ndarray) -> np.ndarray:
        """Quantize an embedding to M uint8 centroid indices.

        Args:
            embedding: Float vector, shape (dim,) or (n, dim).

        Returns:
            Codes array, shape (m,) or (n, m), dtype uint8.
        """
        if not self._trained or self.centroids is None:
            raise RuntimeError("Codebook not trained. Call train() first.")

        single = embedding.ndim == 1
        if single:
            embedding = embedding[np.newaxis, :]

        embedding = embedding.astype(np.float32)
        n = embedding.shape[0]
        codes = np.zeros((n, self.m), dtype=np.uint8)

        for i in range(self.m):
            sub = embedding[:, i * self.sub_dim : (i + 1) * self.sub_dim]
            # Vectorized distance: (n, k)
            dists = (
                np.sum(sub ** 2, axis=1, keepdims=True)
                - 2 * sub @ self.centroids[i].T
                + np.sum(self.centroids[i] ** 2, axis=1)
            )
            codes[:, i] = np.argmin(dists, axis=1).astype(np.uint8)

        return codes[0] if single else codes

    def decode(self, codes: np.ndarray) -> np.ndarray:
        """Reconstruct approximate embedding from centroid indices.

        Args:
            codes: uint8 index array, shape (m,) or (n, m).

        Returns:
            Reconstructed float32 embedding, shape (dim,) or (n, dim).
        """
        if not self._trained or self.centroids is None:
            raise RuntimeError("Codebook not trained. Call train() first.")

        single = codes.ndim == 1
        if single:
            codes = codes[np.newaxis, :]

        n = codes.shape[0]
        reconstructed = np.zeros((n, self.dim), dtype=np.float32)

        for i in range(self.m):
            reconstructed[:, i * self.sub_dim : (i + 1) * self.sub_dim] = (
                self.centroids[i][codes[:, i]]
            )

        return reconstructed[0] if single else reconstructed

    def search(
        self,
        query_embedding: np.ndarray,
        codes: np.ndarray,
        top_k: int = 5,
    ) -> list[tuple[int, float]]:
        """Asymmetric distance search: exact query vs quantized database.

        Pre-computes a distance table (m x k) between the query sub-vectors
        and all centroids, then looks up and sums distances for each database
        entry. This is O(m*k + n*m) instead of O(n*dim).

        Args:
            query_embedding: Exact query vector, shape (dim,).
            codes: Quantized database, shape (n, m), dtype uint8.
            top_k: Number of nearest neighbors.

        Returns:
            List of (index, squared_L2_distance) tuples, ascending by distance.
        """
        if not self._trained or self.centroids is None:
            raise RuntimeError("Codebook not trained. Call train() first.")
        if codes.ndim < 2 or len(codes) == 0:
            return []

        query = query_embedding.astype(np.float32).ravel()

        # Build distance lookup table: (m, k)
        dist_table = np.zeros((self.m, self.k), dtype=np.float32)
        for i in range(self.m):
            sub_q = query[i * self.sub_dim : (i + 1) * self.sub_dim]
            diff = self.centroids[i] - sub_q  # (k, sub_dim)
            dist_table[i] = np.sum(diff ** 2, axis=1)

        # Sum distances for each database vector using the lookup table
        n = codes.shape[0]
        distances = np.zeros(n, dtype=np.float32)
        for i in range(self.m):
            distances += dist_table[i, codes[:, i]]

        k = min(top_k, n)
        indices = np.argpartition(distances, k)[:k]
        indices = indices[np.argsort(distances[indices])]
        return [(int(idx), float(distances[idx])) for idx in indices]

    def save(self, path: Optional[str] = None) -> Path:
        """Persist codebook centroids to disk.

        Args:
            path: File path. Defaults to ~/.engram/index/pq-codebook.npz.

        Returns:
            Path where the codebook was saved.
        """
        if not self._trained or self.centroids is None:
            raise RuntimeError("Codebook not trained. Call train() first.")

        if path is None:
            path = os.path.join(os.path.expanduser("~"), ".engram", "index", "pq-codebook.npz")

        save_path = Path(path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        np.savez(
            str(save_path),
            centroids=self.centroids,
            config=np.array([self.dim, self.m, self.k]),
        )
        return save_path

    @classmethod
    def load(cls, path: Optional[str] = None) -> "PQCodebook":
        """Load a trained codebook from disk.

        Args:
            path: File path. Defaults to ~/.engram/index/pq-codebook.npz.

        Returns:
            Trained PQCodebook instance.
        """
        if path is None:
            path = os.path.join(os.path.expanduser("~"), ".engram", "index", "pq-codebook.npz")

        data = np.load(path)
        config = data["config"]
        dim, m, k = int(config[0]), int(config[1]), int(config[2])

        pq = cls(dim=dim, m=m, k=k)
        pq.centroids = data["centroids"].astype(np.float32)
        pq._trained = True
        return pq

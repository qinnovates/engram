"""
HNSW vector index for approximate nearest neighbor search across tiers.

Each tier maintains its own HNSW graph at its native embedding dimension:
  HOT:    384-d  (full resolution, immediate access)
  WARM:   256-d  (reduced, still high quality)
  COLD:   128-d  (compact, archival recall)
  FROZEN:  64-d  (minimal, deep archive)

Uses hnswlib when available (pip install hnswlib, ~1.3 MB, no server).
Falls back to brute-force numpy cosine similarity when hnswlib is missing.

HNSW parameters tuned for memory workloads:
  M=16             connections per node (balances recall vs memory)
  ef_construction=200  build-time quality (higher = better graph, slower build)
  ef=50            search-time quality (higher = better recall, slower search)
  space='cosine'   similarity metric for float embeddings
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None
    _HAS_NUMPY = False

from .metadata import Tier

logger = logging.getLogger(__name__)

# Tier -> embedding dimension mapping
TIER_DIMENSIONS: dict[str, int] = {
    Tier.HOT: 384,
    Tier.WARM: 256,
    Tier.COLD: 128,
    Tier.FROZEN: 64,
}

# HNSW tuning parameters
HNSW_SPACE = "cosine"
HNSW_M = 16
HNSW_EF_CONSTRUCTION = 200
HNSW_EF_SEARCH = 50

# Default index directory
DEFAULT_INDEX_DIR = Path("~/.engram/index")

# Try to import hnswlib; fall back gracefully
try:
    import hnswlib
    _HAS_HNSWLIB = True
except ImportError:
    _HAS_HNSWLIB = False
    logger.info("hnswlib not installed; using brute-force numpy fallback")


class _TierGraph:
    """A single HNSW graph for one tier's embeddings."""

    def __init__(self, dim: int, tier: str) -> None:
        self.dim = dim
        self.tier = tier
        self._ids: list[str] = []
        self._id_to_label: dict[str, int] = {}
        self._index: Optional[hnswlib.Index] = None  # type: ignore[name-defined]
        self._max_elements = 1024  # initial capacity, grows as needed

    def _ensure_index(self) -> hnswlib.Index:  # type: ignore[name-defined]
        if self._index is None:
            idx = hnswlib.Index(space=HNSW_SPACE, dim=self.dim)  # type: ignore[name-defined]
            idx.init_index(
                max_elements=self._max_elements,
                ef_construction=HNSW_EF_CONSTRUCTION,
                M=HNSW_M,
            )
            idx.set_ef(HNSW_EF_SEARCH)
            self._index = idx
        return self._index

    def _grow_if_needed(self) -> None:
        """Double capacity when the index is full."""
        idx = self._ensure_index()
        if len(self._ids) >= self._max_elements:
            self._max_elements *= 2
            idx.resize_index(self._max_elements)

    def add(self, artifact_id: str, embedding: np.ndarray) -> None:
        if embedding.shape != (self.dim,):
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.dim}, "
                f"got {embedding.shape}"
            )
        if artifact_id in self._id_to_label:
            # Update existing embedding
            label = self._id_to_label[artifact_id]
        else:
            label = len(self._ids)
            self._ids.append(artifact_id)
            self._id_to_label[artifact_id] = label

        self._grow_if_needed()
        idx = self._ensure_index()
        idx.add_items(embedding.reshape(1, -1).astype(np.float32), [label])

    def search(
        self, query: np.ndarray, top_k: int = 10
    ) -> list[tuple[str, float]]:
        if self._index is None or len(self._ids) == 0:
            return []
        if query.shape != (self.dim,):
            return []  # dimension mismatch — skip this tier

        k = min(top_k, len(self._ids))
        labels, distances = self._index.knn_query(
            query.reshape(1, -1).astype(np.float32), k=k
        )
        results = []
        for label, dist in zip(labels[0], distances[0]):
            label = int(label)
            if label < len(self._ids):
                # cosine space returns 1 - cosine_similarity; convert to similarity
                similarity = 1.0 - float(dist)
                results.append((self._ids[label], similarity))
        return results

    @property
    def count(self) -> int:
        return len(self._ids)

    def save(self, path: Path) -> None:
        if self._index is not None and len(self._ids) > 0:
            self._index.save_index(str(path))

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        idx = hnswlib.Index(space=HNSW_SPACE, dim=self.dim)  # type: ignore[name-defined]
        idx.load_index(str(path))
        idx.set_ef(HNSW_EF_SEARCH)
        self._index = idx
        self._max_elements = idx.get_max_elements()


class _BruteForceTierGraph:
    """Brute-force fallback using numpy cosine similarity."""

    def __init__(self, dim: int, tier: str) -> None:
        self.dim = dim
        self.tier = tier
        self._ids: list[str] = []
        self._id_to_idx: dict[str, int] = {}
        self._embeddings: list[np.ndarray] = []

    def add(self, artifact_id: str, embedding: np.ndarray) -> None:
        if embedding.shape != (self.dim,):
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.dim}, "
                f"got {embedding.shape}"
            )
        if artifact_id in self._id_to_idx:
            idx = self._id_to_idx[artifact_id]
            self._embeddings[idx] = embedding.astype(np.float32)
        else:
            self._id_to_idx[artifact_id] = len(self._ids)
            self._ids.append(artifact_id)
            self._embeddings.append(embedding.astype(np.float32))

    def search(
        self, query: np.ndarray, top_k: int = 10
    ) -> list[tuple[str, float]]:
        if not self._embeddings:
            return []
        if query.shape != (self.dim,):
            return []  # dimension mismatch — skip this tier

        q = query.astype(np.float32)
        q_norm = np.linalg.norm(q)
        if q_norm == 0:
            return []
        q = q / q_norm

        matrix = np.stack(self._embeddings)
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        # Avoid division by zero
        norms = np.where(norms == 0, 1.0, norms)
        matrix = matrix / norms

        similarities = matrix @ q
        k = min(top_k, len(self._ids))
        top_indices = np.argpartition(-similarities, k)[:k]
        top_indices = top_indices[np.argsort(-similarities[top_indices])]

        return [
            (self._ids[int(i)], float(similarities[i]))
            for i in top_indices
        ]

    @property
    def count(self) -> int:
        return len(self._ids)

    def save(self, path: Path) -> None:
        if self._embeddings:
            data = {
                "ids": self._ids,
                "embeddings": np.stack(self._embeddings).tolist(),
            }
            import json
            path.write_text(json.dumps(data))

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        import json
        data = json.loads(path.read_text())
        self._ids = data["ids"]
        self._embeddings = [
            np.array(e, dtype=np.float32) for e in data["embeddings"]
        ]
        self._id_to_idx = {aid: i for i, aid in enumerate(self._ids)}


class HNSWIndex:
    """
    Multi-tier HNSW vector index for artifact similarity search.

    Maintains separate graphs per tier, each at its native embedding
    dimension. Search merges results across all tiers by similarity score.

    Falls back to brute-force numpy when hnswlib is not installed.
    """

    def __init__(self) -> None:
        graph_cls = _TierGraph if _HAS_HNSWLIB else _BruteForceTierGraph
        self._graphs: dict[str, _TierGraph | _BruteForceTierGraph] = {}
        for tier_val, dim in TIER_DIMENSIONS.items():
            tier_str = tier_val if isinstance(tier_val, str) else tier_val.value
            self._graphs[tier_str] = graph_cls(dim=dim, tier=tier_str)
        self._backend = "hnswlib" if _HAS_HNSWLIB else "numpy"

    @property
    def backend(self) -> str:
        """Return which backend is active: 'hnswlib' or 'numpy'."""
        return self._backend

    def add(self, artifact_id: str, embedding: np.ndarray, tier: str) -> None:
        """
        Add an embedding to the appropriate tier graph.

        Args:
            artifact_id: Unique identifier for the artifact.
            embedding: Numpy array of shape (dim,) matching the tier's dimension.
            tier: One of 'hot', 'warm', 'cold', 'frozen'.

        Raises:
            ValueError: If tier is unknown or embedding dimension mismatches.
        """
        tier_key = tier if isinstance(tier, str) else tier.value
        if tier_key not in self._graphs:
            raise ValueError(
                f"Unknown tier '{tier_key}'. "
                f"Valid tiers: {list(self._graphs.keys())}"
            )
        self._graphs[tier_key].add(artifact_id, embedding)

    def search(
        self, query_embedding: np.ndarray, top_k: int = 10
    ) -> list[tuple[str, float]]:
        """
        Search all tier graphs and return top_k results merged by score.

        The query is tried against each tier graph. Only graphs whose
        dimension matches the query vector length are searched. Results
        are merged and sorted by descending similarity.

        Args:
            query_embedding: Query vector. Will be matched against tiers
                             with the same dimension.
            top_k: Maximum number of results to return.

        Returns:
            List of (artifact_id, similarity_score) tuples, sorted by
            descending similarity. Scores are cosine similarities in [0, 1].
        """
        all_results: list[tuple[str, float]] = []
        for graph in self._graphs.values():
            results = graph.search(query_embedding, top_k=top_k)
            all_results.extend(results)

        # Sort by similarity descending, deduplicate by artifact_id
        seen: set[str] = set()
        merged: list[tuple[str, float]] = []
        for aid, score in sorted(all_results, key=lambda x: -x[1]):
            if aid not in seen:
                seen.add(aid)
                merged.append((aid, score))
                if len(merged) >= top_k:
                    break
        return merged

    def save(self, index_dir: Optional[Path] = None) -> None:
        """
        Persist all tier graphs to disk.

        Saves to index_dir/hnsw-{tier}.bin (hnswlib) or
        index_dir/hnsw-{tier}.json (numpy fallback).

        Args:
            index_dir: Directory to save index files. Defaults to
                       ~/.engram/index/.
        """
        if index_dir is None:
            index_dir = Path(DEFAULT_INDEX_DIR).expanduser()
        index_dir = Path(index_dir)
        index_dir.mkdir(parents=True, exist_ok=True)

        ext = ".bin" if _HAS_HNSWLIB else ".json"
        for tier_key, graph in self._graphs.items():
            path = index_dir / f"hnsw-{tier_key}{ext}"
            graph.save(path)

    def load(self, index_dir: Optional[Path] = None) -> None:
        """
        Load tier graphs from disk.

        Args:
            index_dir: Directory containing index files. Defaults to
                       ~/.engram/index/.
        """
        if index_dir is None:
            index_dir = Path(DEFAULT_INDEX_DIR).expanduser()
        index_dir = Path(index_dir)

        if not index_dir.exists():
            return  # No index saved yet

        ext = ".bin" if _HAS_HNSWLIB else ".json"
        for tier_key, graph in self._graphs.items():
            path = index_dir / f"hnsw-{tier_key}{ext}"
            graph.load(path)

    def rebuild(self) -> None:
        """
        Clear and reinitialize all tier graphs.

        After rebuild(), the index is empty. Re-add all embeddings
        to repopulate.
        """
        graph_cls = _TierGraph if _HAS_HNSWLIB else _BruteForceTierGraph
        for tier_key in list(self._graphs.keys()):
            dim = TIER_DIMENSIONS[Tier(tier_key)]
            self._graphs[tier_key] = graph_cls(dim=dim, tier=tier_key)

    def stats(self) -> dict[str, int]:
        """Return count of embeddings per tier."""
        return {tier: graph.count for tier, graph in self._graphs.items()}

    def total_count(self) -> int:
        """Return total number of embeddings across all tiers."""
        return sum(graph.count for graph in self._graphs.values())

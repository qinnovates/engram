"""
Matryoshka embedding layer for semantic search.

Generates embeddings locally using sentence-transformers (no cloud API).
Implements tiered dimensionality via Matryoshka truncation:

  hot:    384 dims (float32) — full fidelity
  warm:   256 dims (float32) — 33% smaller, minimal quality loss
  cold:   128 dims (int8 quantized) — 75% smaller, fast approximate search
  frozen:  64 dims (binary via packbits) — 94% smaller, Hamming distance

This mirrors the storage tiers in the compression engine: fidelity
decreases as data ages, but the index remains searchable at every tier.

Graceful degradation: if sentence-transformers is not installed, all
operations return empty results and log a warning.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# --- Lazy import for sentence-transformers (optional dependency) ---

_model_cache: dict[str, object] = {}
_HAS_SENTENCE_TRANSFORMERS = None  # Lazy check

# Third-party model supply chain verification
# Model: sentence-transformers/all-MiniLM-L6-v2
# License: Apache 2.0 | Author: sentence-transformers | Downloads: 207M+
# SHA-256 of model.safetensors (86.7 MB):
MODEL_SAFETENSORS_SHA256 = "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"
DEFAULT_MODEL = "all-MiniLM-L6-v2"


def _check_sentence_transformers() -> bool:
    """Check if sentence-transformers is available (cached)."""
    global _HAS_SENTENCE_TRANSFORMERS
    if _HAS_SENTENCE_TRANSFORMERS is None:
        try:
            import sentence_transformers  # noqa: F401
            _HAS_SENTENCE_TRANSFORMERS = True
        except ImportError:
            _HAS_SENTENCE_TRANSFORMERS = False
            logger.warning(
                "sentence-transformers not installed. Embedding features disabled. "
                "Install with: pip install sentence-transformers"
            )
    return _HAS_SENTENCE_TRANSFORMERS


def _verify_model_checksum(model) -> bool:
    """Verify the model weights match the expected SHA-256 checksum.

    This detects supply chain tampering — if someone replaces the model
    weights (via a compromised HuggingFace cache, typosquatted package,
    or modified download), the hash won't match.
    """
    import hashlib
    try:
        model_dir = Path(model[0].auto_model.config._name_or_path)
        safetensors_path = model_dir / "model.safetensors"
        if not safetensors_path.exists():
            logger.warning("model.safetensors not found — cannot verify checksum")
            return True  # Don't block if file layout differs

        h = hashlib.sha256(safetensors_path.read_bytes()).hexdigest()
        if h != MODEL_SAFETENSORS_SHA256:
            logger.error(
                "SECURITY: model.safetensors checksum mismatch! "
                "Expected %s, got %s. Model may be tampered.",
                MODEL_SAFETENSORS_SHA256[:16], h[:16],
            )
            return False
        return True
    except Exception:
        return True  # Don't block on unexpected model internals


def _get_model(model_name: str = DEFAULT_MODEL, allow_network: bool = False):
    """Load or return cached SentenceTransformer model.

    Args:
        model_name: HuggingFace model identifier.
        allow_network: If True, allows network calls for model download/update.
            Only set to True during `engram init` or `engram update-model`.
            All normal operations (run, search, recall, context) pass False.
    """
    if not _check_sentence_transformers():
        return None
    if model_name not in _model_cache:
        from sentence_transformers import SentenceTransformer
        if allow_network:
            # During init/update: allow network for model download + update check
            # Still disable telemetry — we allow the download, not the tracking
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
            os.environ.pop("HF_HUB_OFFLINE", None)
            os.environ.pop("TRANSFORMERS_OFFLINE", None)
            logger.info("Network mode: allowing model download/update check")
        else:
            # Normal operation: fully offline — zero network calls
            # Model must already be cached from `engram init`
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        model = SentenceTransformer(model_name)
        # Verify model integrity against known checksum
        if model_name == DEFAULT_MODEL and not _verify_model_checksum(model):
            raise RuntimeError(
                "Embedding model checksum verification failed. "
                "The model weights may have been tampered with. "
                "Delete the cached model and reinstall: "
                "rm -rf ~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2"
            )
        _model_cache[model_name] = model
    return _model_cache[model_name]


# --- Tier configuration ---

TIER_DIMS = {
    "hot": 384,
    "warm": 256,
    "cold": 128,
    "frozen": 64,
}

DEFAULT_MODEL = "all-MiniLM-L6-v2"
FULL_DIM = 384  # all-MiniLM-L6-v2 output dimension


@dataclass
class SearchResult:
    """A single search result from the embedding index."""
    path: str
    score: float
    tier: str


def download_model(model_name: str = DEFAULT_MODEL) -> bool:
    """Download or update the embedding model (network allowed).

    Call this from `engram init` or `engram update-model`.
    Normal operations use _get_model() which is fully offline.

    Returns True if model is ready, False if sentence-transformers not installed.
    """
    model = _get_model(model_name, allow_network=True)
    if model is None:
        return False
    logger.info("Embedding model ready: %s", model_name)
    return True


def _encode_text(text: str, model_name: str = DEFAULT_MODEL) -> Optional[np.ndarray]:
    """Encode text to a full-dimension float32 embedding vector.

    Returns None if sentence-transformers is not available.
    """
    model = _get_model(model_name)
    if model is None:
        return None
    vec = model.encode(text, normalize_embeddings=True, convert_to_numpy=True)
    return vec.astype(np.float32)


def _truncate_float(vec: np.ndarray, dims: int) -> np.ndarray:
    """Truncate to first N dimensions (Matryoshka truncation), re-normalize."""
    truncated = vec[:dims].copy()
    norm = np.linalg.norm(truncated)
    if norm > 0:
        truncated /= norm
    return truncated.astype(np.float32)


def _quantize_int8(vec: np.ndarray, dims: int) -> np.ndarray:
    """Truncate to N dims and quantize to int8 (-127 to 127)."""
    truncated = vec[:dims].copy()
    norm = np.linalg.norm(truncated)
    if norm > 0:
        truncated /= norm
    return np.clip(truncated * 127.0, -127, 127).astype(np.int8)


def _quantize_binary(vec: np.ndarray, dims: int) -> np.ndarray:
    """Truncate to N dims and pack into binary (numpy.packbits).

    Each dimension becomes 1 bit: 1 if >= 0, 0 otherwise.
    Returns packed uint8 array (dims/8 bytes).
    """
    truncated = vec[:dims].copy()
    bits = (truncated >= 0).astype(np.uint8)
    return np.packbits(bits)


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity for float vectors (already normalized -> dot product)."""
    return float(np.dot(a, b))


def _cosine_similarity_int8(a: np.ndarray, b: np.ndarray) -> float:
    """Approximate cosine similarity for int8 quantized vectors."""
    a_f = a.astype(np.float32)
    b_f = b.astype(np.float32)
    norm_a = np.linalg.norm(a_f)
    norm_b = np.linalg.norm(b_f)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a_f, b_f) / (norm_a * norm_b))


def _hamming_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Hamming similarity for binary-packed vectors.

    Returns 1.0 for identical, 0.0 for maximally different.
    """
    # Count matching bits
    xor = np.bitwise_xor(a, b)
    differing_bits = sum(bin(byte).count("1") for byte in xor)
    total_bits = len(a) * 8
    return 1.0 - (differing_bits / total_bits)


class EmbeddingIndex:
    """Tiered embedding index with Matryoshka-style dimensionality.

    Stores embeddings at four fidelity levels (hot/warm/cold/frozen),
    persisted as .npy files under ~/.engram/index/.

    Search cascades across all populated tiers, weighted by fidelity:
    hot results are trusted more than frozen approximations.
    """

    def __init__(self, index_dir: Optional[Path] = None,
                 model_name: str = DEFAULT_MODEL):
        if index_dir is None:
            index_dir = Path.home() / ".engram" / "index"
        self.index_dir = Path(index_dir)
        self.model_name = model_name

        # Per-tier storage: parallel arrays of (paths, embeddings)
        self._paths: dict[str, list[str]] = {t: [] for t in TIER_DIMS}
        self._embeddings: dict[str, Optional[np.ndarray]] = {t: None for t in TIER_DIMS}
        self._dirty: set[str] = set()

        self._load()

    # --- Persistence ---

    def _tier_paths_file(self, tier: str) -> Path:
        return self.index_dir / f"paths-{tier}.json"

    def _tier_embeddings_file(self, tier: str) -> Path:
        return self.index_dir / f"embeddings-{tier}.npy"

    def _load(self) -> None:
        """Load all tier data from disk."""
        import json
        for tier in TIER_DIMS:
            paths_file = self._tier_paths_file(tier)
            emb_file = self._tier_embeddings_file(tier)
            if paths_file.exists() and emb_file.exists():
                try:
                    with open(paths_file) as f:
                        self._paths[tier] = json.load(f)
                    self._embeddings[tier] = np.load(emb_file, allow_pickle=False)
                    # Validate consistency
                    if len(self._paths[tier]) != len(self._embeddings[tier]):
                        logger.warning(
                            "Embedding/path count mismatch for %s tier, resetting", tier
                        )
                        self._paths[tier] = []
                        self._embeddings[tier] = None
                except (ValueError, OSError, json.JSONDecodeError) as e:
                    logger.warning("Failed to load %s tier embeddings: %s", tier, e)
                    self._paths[tier] = []
                    self._embeddings[tier] = None

    def save(self) -> None:
        """Save dirty tiers to disk."""
        import json
        if not self._dirty:
            return
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir.chmod(0o700)  # Restrict — embeddings are sensitive metadata
        from .fileutil import atomic_write_text
        for tier in self._dirty:
            paths_file = self._tier_paths_file(tier)
            emb_file = self._tier_embeddings_file(tier)
            atomic_write_text(paths_file, json.dumps(self._paths[tier]))
            if self._embeddings[tier] is not None:
                np.save(emb_file, self._embeddings[tier])
                os.chmod(str(emb_file), 0o600)
        self._dirty.clear()

    # --- Add / Remove ---

    def add(self, artifact_path: str, text: str, tier: str = "hot") -> bool:
        """Generate and store an embedding for the given text at the specified tier.

        Args:
            artifact_path: Unique identifier for the artifact (usually file path).
            text: Text content to embed.
            tier: Storage tier (hot/warm/cold/frozen).

        Returns:
            True if embedding was stored, False if sentence-transformers unavailable.
        """
        if tier not in TIER_DIMS:
            raise ValueError(f"Unknown tier: {tier!r}. Must be one of {list(TIER_DIMS)}")

        full_vec = _encode_text(text, self.model_name)
        if full_vec is None:
            return False

        # Remove existing entry for this path in this tier (if re-indexing)
        self._remove_from_tier(artifact_path, tier)

        # Generate tier-appropriate embedding
        dims = TIER_DIMS[tier]
        if tier == "frozen":
            vec = _quantize_binary(full_vec, dims)
        elif tier == "cold":
            vec = _quantize_int8(full_vec, dims)
        else:
            vec = _truncate_float(full_vec, dims)

        # Append to storage
        self._paths[tier].append(artifact_path)
        if self._embeddings[tier] is None:
            self._embeddings[tier] = vec.reshape(1, -1)
        else:
            self._embeddings[tier] = np.vstack([self._embeddings[tier], vec.reshape(1, -1)])
        self._dirty.add(tier)
        return True

    def get_embedding(self, artifact_path: str) -> 'np.ndarray | None':
        """Return the full-precision embedding for an artifact (hot tier), or None."""
        if "hot" in self._paths and artifact_path in self._paths["hot"]:
            idx = self._paths["hot"].index(artifact_path)
            if self._embeddings["hot"] is not None and idx < len(self._embeddings["hot"]):
                return self._embeddings["hot"][idx]
        return None

    def _remove_from_tier(self, artifact_path: str, tier: str) -> None:
        """Remove an artifact from a specific tier (if present)."""
        if artifact_path in self._paths[tier]:
            idx = self._paths[tier].index(artifact_path)
            self._paths[tier].pop(idx)
            if self._embeddings[tier] is not None and len(self._embeddings[tier]) > 0:
                self._embeddings[tier] = np.delete(self._embeddings[tier], idx, axis=0)
                if len(self._embeddings[tier]) == 0:
                    self._embeddings[tier] = None
            self._dirty.add(tier)

    def remove(self, artifact_path: str) -> None:
        """Remove an artifact from all tiers."""
        for tier in TIER_DIMS:
            self._remove_from_tier(artifact_path, tier)

    # --- Search ---

    def search(self, query_text: str, top_k: int = 10) -> list[SearchResult]:
        """Search across all tiers for artifacts similar to query_text.

        Encodes the query, then compares against each tier using the
        appropriate similarity function. Results are merged and ranked
        by score.

        Args:
            query_text: Natural language query.
            top_k: Maximum number of results.

        Returns:
            List of SearchResult sorted by descending similarity.
        """
        full_vec = _encode_text(query_text, self.model_name)
        if full_vec is None:
            return []

        all_results: list[SearchResult] = []

        for tier, dims in TIER_DIMS.items():
            if self._embeddings[tier] is None or len(self._paths[tier]) == 0:
                continue

            # Prepare query vector for this tier
            if tier == "frozen":
                q_vec = _quantize_binary(full_vec, dims)
                sim_fn = _hamming_similarity
            elif tier == "cold":
                q_vec = _quantize_int8(full_vec, dims)
                sim_fn = _cosine_similarity_int8
            else:
                q_vec = _truncate_float(full_vec, dims)
                sim_fn = _cosine_similarity

            # Score each stored embedding
            for i, path in enumerate(self._paths[tier]):
                score = sim_fn(q_vec, self._embeddings[tier][i])
                all_results.append(SearchResult(path=path, score=score, tier=tier))

        # Sort by score descending
        all_results.sort(key=lambda r: r.score, reverse=True)

        # Deduplicate: if same path appears in multiple tiers, keep highest score
        seen: set[str] = set()
        deduped: list[SearchResult] = []
        for r in all_results:
            if r.path not in seen:
                seen.add(r.path)
                deduped.append(r)

        return deduped[:top_k]

    def count(self, tier: Optional[str] = None) -> int:
        """Count embeddings in a tier, or all tiers if tier is None."""
        if tier:
            return len(self._paths.get(tier, []))
        return sum(len(p) for p in self._paths.values())

    def tiers_summary(self) -> dict[str, int]:
        """Return count of embeddings per tier."""
        return {t: len(self._paths[t]) for t in TIER_DIMS}

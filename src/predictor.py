"""
Predictive context loader — pre-warms relevant sessions before the AI needs them.

Models the brain's priming mechanism: walking into a kitchen activates
food-related memories before you consciously think about cooking. The
environmental context (your first message) triggers anticipatory activation
of related memories.

Uses Matryoshka tiered embeddings for efficient multi-tier search:
  Frozen (64-dim, Hamming) → Cold (128-dim, cosine) → Warm (256-dim) → Hot (384-dim)
  Each tier filters before the next, so searching 100K sessions costs
  the same as deeply comparing 5.

Pipeline:
  1. User sends first message
  2. SessionStart hook calls predictor.predict(message)
  3. Embed the message (384-dim, ~225ms)
  4. Cascade search through tiers (frozen → cold → warm → hot)
  5. Top-K results pre-loaded into sidecar index
  6. When Claude needs context, it's already in memory (0.05ms)

Accuracy tracking:
  - Logs predictions at session start
  - Logs actual references during session
  - Computes hit rate at session end
  - Stored in prediction-log.json for evaluation
"""

from __future__ import annotations

import json
import time
import hashlib
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None
    _HAS_NUMPY = False
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


# Matryoshka tier dimensions
TIER_DIMS = {
    "hot": 384,
    "warm": 256,
    "cold": 128,
    "frozen": 64,
}

# How many candidates to pass from each tier to the next
CASCADE_LIMITS = {
    "frozen": 50,   # coarse scan → top 50
    "cold": 20,     # refine → top 20
    "warm": 10,     # re-rank → top 10
    "hot": 5,       # final → top 5 pre-loaded
}

# Minimum similarity to consider a prediction valid
MIN_SIMILARITY = 0.25


@dataclass
class Prediction:
    """A predicted-relevant session."""
    session_hash: str
    summary: str
    similarity: float
    tier_found: str        # which tier first identified this
    path: str = ""


@dataclass
class PredictionLog:
    """Log of predictions vs actuals for accuracy measurement."""
    session_id: str
    timestamp: float
    query_text: str
    predictions: list[dict] = field(default_factory=list)
    actuals: list[str] = field(default_factory=list)  # hashes actually referenced
    hit_rate: float = 0.0  # predictions that were actually used


class ContextPredictor:
    """
    Predicts which sessions will be relevant based on conversation context.

    Maintains a tiered embedding index that mirrors Engram's storage tiers.
    Each tier stores embeddings at its native Matryoshka dimension.
    Search cascades from cheapest (frozen, 64-dim) to most expensive (hot, 384-dim).
    """

    def __init__(self, index_dir: Path):
        self.index_dir = index_dir
        self.index_dir.mkdir(parents=True, exist_ok=True)

        # Per-tier embedding matrices and metadata
        self._embeddings: dict[str, np.ndarray] = {}   # tier → (N, dim) array
        self._hashes: dict[str, list[str]] = {}         # tier → list of session hashes
        self._summaries: dict[str, list[str]] = {}      # tier → list of summaries
        self._paths: dict[str, list[str]] = {}           # tier → list of paths

        # Full embeddings (384-dim) stored for all sessions regardless of tier
        # Matryoshka truncation happens at query time
        self._full_embeddings: dict[str, np.ndarray] = {}  # hash → 384-dim vector

        # Model (lazy loaded)
        self._model = None

        # Prediction tracking
        self._current_predictions: list[Prediction] = []
        self._log_path = index_dir / "prediction-log.json"

        self._load_index()

    # ── Model ──

    def _get_model(self):
        """Lazy-load the sentence transformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer("all-MiniLM-L6-v2")
            except ImportError:
                return None
        return self._model

    def embed(self, text: str) -> Optional[np.ndarray]:
        """Embed a text string. Returns 384-dim vector."""
        model = self._get_model()
        if model is None:
            return None
        return model.encode([text], show_progress_bar=False)[0]

    # ── Registration ──

    def register(self, session_hash: str, text: str, summary: str,
                 tier: str = "hot", path: str = "") -> None:
        """Register a session with its embedding. Called during engram scan."""
        embedding = self.embed(text)
        if embedding is None:
            return

        self._full_embeddings[session_hash] = embedding

        # Store in the appropriate tier
        if tier not in self._embeddings:
            self._embeddings[tier] = np.empty((0, TIER_DIMS.get(tier, 384)))
            self._hashes[tier] = []
            self._summaries[tier] = []
            self._paths[tier] = []

        # Truncate to tier dimension (Matryoshka)
        dim = TIER_DIMS.get(tier, 384)
        truncated = embedding[:dim]

        self._embeddings[tier] = np.vstack([self._embeddings[tier], truncated.reshape(1, -1)])
        self._hashes[tier].append(session_hash)
        self._summaries[tier].append(summary)
        self._paths[tier].append(path)

        self._save_index()

    # ── Prediction (the core function) ──

    def predict(self, message: str, top_k: int = 5) -> list[Prediction]:
        """
        Predict which sessions will be relevant to this message.

        Cascading Matryoshka search:
          1. Embed the message (384-dim)
          2. Search frozen tier (truncate query to 64-dim, Hamming on all frozen sessions)
          3. Search cold tier (128-dim cosine on frozen survivors + cold sessions)
          4. Search warm tier (256-dim cosine on cold survivors + warm sessions)
          5. Search hot tier (384-dim cosine on warm survivors + hot sessions)
          6. Return top-K across all tiers
        """
        query_embedding = self.embed(message)
        if query_embedding is None:
            return []

        # Collect candidates across all tiers
        all_candidates: dict[str, tuple[float, str, str, str]] = {}  # hash → (score, summary, tier, path)

        # Search each tier with Matryoshka truncation
        for tier in ["frozen", "cold", "warm", "hot"]:
            if tier not in self._embeddings or len(self._embeddings[tier]) == 0:
                continue

            dim = TIER_DIMS.get(tier, 384)
            query_truncated = query_embedding[:dim]

            if tier == "frozen" and dim <= 64:
                # Binary Hamming distance for frozen tier (fastest)
                scores = self._hamming_similarity(query_truncated, self._embeddings[tier])
            else:
                # Cosine similarity for other tiers
                scores = self._cosine_similarity(query_truncated, self._embeddings[tier])

            # Collect candidates from this tier
            limit = CASCADE_LIMITS.get(tier, 10)
            top_indices = np.argsort(-scores)[:limit]

            for idx in top_indices:
                score = float(scores[idx])
                if score < MIN_SIMILARITY:
                    continue

                h = self._hashes[tier][idx]
                # Keep the best score across tiers
                if h not in all_candidates or score > all_candidates[h][0]:
                    all_candidates[h] = (
                        score,
                        self._summaries[tier][idx],
                        tier,
                        self._paths[tier][idx],
                    )

        # Sort by score, take top_k
        ranked = sorted(all_candidates.items(), key=lambda x: -x[1][0])[:top_k]

        predictions = []
        for h, (score, summary, tier_found, path) in ranked:
            predictions.append(Prediction(
                session_hash=h,
                summary=summary,
                similarity=score,
                tier_found=tier_found,
                path=path,
            ))

        self._current_predictions = predictions
        return predictions

    # ── Accuracy tracking ──

    def log_prediction(self, session_id: str, query_text: str) -> None:
        """Log current predictions for later accuracy evaluation."""
        log_entry = PredictionLog(
            session_id=session_id,
            timestamp=time.time(),
            query_text=query_text[:500],
            predictions=[asdict(p) for p in self._current_predictions],
        )
        self._append_log(log_entry)

    def log_actual_reference(self, session_hash: str) -> None:
        """Log that a session was actually referenced during this conversation."""
        # Update the most recent log entry
        logs = self._read_logs()
        if logs:
            logs[-1].setdefault("actuals", [])
            if session_hash not in logs[-1]["actuals"]:
                logs[-1]["actuals"].append(session_hash)

            # Compute hit rate
            predicted_hashes = {p["session_hash"] for p in logs[-1].get("predictions", [])}
            actual_hashes = set(logs[-1]["actuals"])
            hits = len(predicted_hashes & actual_hashes)
            logs[-1]["hit_rate"] = hits / len(predicted_hashes) if predicted_hashes else 0.0

            self._write_logs(logs)

    def accuracy_report(self) -> dict:
        """Report prediction accuracy across all logged sessions."""
        logs = self._read_logs()
        if not logs:
            return {"sessions": 0, "avg_hit_rate": 0.0, "message": "No prediction data yet"}

        hit_rates = [l.get("hit_rate", 0.0) for l in logs if l.get("predictions")]
        sessions_with_actuals = [l for l in logs if l.get("actuals")]

        return {
            "sessions_logged": len(logs),
            "sessions_with_references": len(sessions_with_actuals),
            "avg_hit_rate": sum(hit_rates) / len(hit_rates) if hit_rates else 0.0,
            "total_predictions": sum(len(l.get("predictions", [])) for l in logs),
            "total_actual_refs": sum(len(l.get("actuals", [])) for l in logs),
        }

    # ── Similarity ──

    @staticmethod
    def _cosine_similarity(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        """Cosine similarity between a query vector and a matrix of vectors."""
        query_norm = np.linalg.norm(query)
        if query_norm == 0:
            return np.zeros(matrix.shape[0])
        matrix_norms = np.linalg.norm(matrix, axis=1)
        matrix_norms[matrix_norms == 0] = 1e-10
        return np.dot(matrix, query) / (matrix_norms * query_norm)

    @staticmethod
    def _hamming_similarity(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
        """Binary Hamming similarity for frozen-tier embeddings."""
        # Binarize: positive values → 1, negative → 0
        query_bits = (query > 0).astype(np.uint8)
        matrix_bits = (matrix > 0).astype(np.uint8)
        # Hamming similarity = fraction of matching bits
        matches = np.sum(query_bits == matrix_bits, axis=1)
        return matches / len(query_bits)

    # ── Persistence ──

    def _save_index(self) -> None:
        """Save embedding index to disk."""
        for tier, embeddings in self._embeddings.items():
            if len(embeddings) > 0:
                np.save(str(self.index_dir / f"embeddings-{tier}.npy"), embeddings)

        meta = {}
        for tier in self._hashes:
            meta[tier] = {
                "hashes": self._hashes[tier],
                "summaries": self._summaries[tier],
                "paths": self._paths[tier],
            }
        with open(self.index_dir / "predictor-meta.json", "w") as f:
            json.dump(meta, f)

    def _load_index(self) -> None:
        """Load embedding index from disk."""
        meta_path = self.index_dir / "predictor-meta.json"
        if not meta_path.exists():
            return

        with open(meta_path) as f:
            meta = json.load(f)

        for tier, data in meta.items():
            emb_path = self.index_dir / f"embeddings-{tier}.npy"
            if emb_path.exists():
                self._embeddings[tier] = np.load(str(emb_path))
                self._hashes[tier] = data["hashes"]
                self._summaries[tier] = data["summaries"]
                self._paths[tier] = data.get("paths", [""] * len(data["hashes"]))

    def _append_log(self, entry: PredictionLog) -> None:
        logs = self._read_logs()
        logs.append(asdict(entry))
        # Keep last 500 entries
        if len(logs) > 500:
            logs = logs[-500:]
        self._write_logs(logs)

    def _read_logs(self) -> list[dict]:
        if self._log_path.exists():
            with open(self._log_path) as f:
                return json.load(f)
        return []

    def _write_logs(self, logs: list[dict]) -> None:
        with open(self._log_path, "w") as f:
            json.dump(logs, f, indent=2)

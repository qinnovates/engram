"""
Activation graph — co-occurrence tracking + spreading activation.

Layer 3: PMI co-occurrence — tracks which artifacts are recalled together.
Layer 4: Spreading activation — weighted BFS propagation to find related artifacts.

All graph state lives in the Rust sidecar's mlocked memory. Never written to disk.
Rebuilt from co-occurrence events each session. Ephemeral by design — no persistence
means no attack surface at rest.

Python side is a thin wrapper around sidecar GRAPH_* commands.
"""

from __future__ import annotations

import json
import re
from typing import Optional

# Strict hex validation: exactly 64 chars of [0-9a-f], no newlines/spaces/nulls
_HEX_HASH_RE = re.compile(r'^[0-9a-f]{64}$')


def _validate_hex_hash(h: str) -> bool:
    """Validate that h is exactly a 64-char lowercase hex string.

    Prevents protocol injection via crafted sha256 values containing
    newlines, spaces, or other control characters that could be
    interpreted as sidecar command delimiters.
    """
    if not h or not isinstance(h, str):
        return False
    return _HEX_HASH_RE.match(h) is not None


class CoGraph:
    """Client for the Rust sidecar's activation graph.

    Records artifact access events during a session, flushes co-occurrence
    edges at session boundaries, and queries spreading activation for
    related artifact discovery.
    """

    def __init__(self, vault_client=None) -> None:
        self._vault = vault_client

    def record_access(self, sha256_hex: str) -> None:
        """Record that an artifact was accessed in the current session.

        Call this on every recall() and context-build inclusion.
        The sidecar buffers accesses and creates co-occurrence edges
        when flush_session() is called.
        """
        if not self._vault or not sha256_hex:
            return
        if not _validate_hex_hash(sha256_hex):
            return
        try:
            response = self._vault._send(f"GRAPH_RECORD {sha256_hex}")
            if not response.startswith("OK"):
                pass  # Non-fatal
        except Exception:
            pass  # Activation tracking is supplementary

    def flush_session(self) -> None:
        """End the current session — create co-occurrence edges.

        Call this at the end of each get_context() / recall batch.
        All artifacts recorded since the last flush get pairwise edges.
        """
        if not self._vault:
            return
        try:
            self._vault._send("GRAPH_FLUSH")
        except Exception:
            pass

    def add_keyword_edge(self, hash_a: str, hash_b: str, jaccard: float) -> None:
        """Add a keyword-overlap edge between two artifacts."""
        if not self._vault:
            return
        if not _validate_hex_hash(hash_a) or not _validate_hex_hash(hash_b):
            return
        # Reject NaN, Inf, negative, and out-of-range floats
        if not (isinstance(jaccard, (int, float)) and 0.0 < jaccard <= 1.0):
            return
        import math
        if math.isnan(jaccard) or math.isinf(jaccard):
            return
        try:
            self._vault._send(
                f"GRAPH_KEYWORD_EDGE {hash_a} {hash_b} {jaccard:.4f}"
            )
        except Exception:
            pass

    def get_related(
        self,
        sha256_hex: str,
        depth: int = 2,
        top_k: int = 3,
    ) -> list[dict]:
        """Get related artifacts via spreading activation.

        Returns list of {"hash": "...", "score": 0.85} dicts,
        sorted by activation score descending.
        """
        if not self._vault or not _validate_hex_hash(sha256_hex):
            return []
        # Clamp to safe bounds (defense in depth — sidecar also caps these)
        depth = max(1, min(int(depth), 3))
        top_k = max(1, min(int(top_k), 20))
        try:
            response = self._vault._send(
                f"GRAPH_ACTIVATE {sha256_hex} {depth} {top_k}"
            )
            if response.startswith("OK "):
                json_str = response[3:].strip()
                # Length guard: max 20 results × ~80 bytes each = ~1600 bytes
                if json_str and json_str != "[]" and len(json_str) <= 4096:
                    return json.loads(json_str)
            return []
        except Exception:
            return []

    def stats(self) -> Optional[dict]:
        """Get graph statistics."""
        if not self._vault:
            return None
        try:
            response = self._vault._send("GRAPH_STATS")
            if response.startswith("OK "):
                return json.loads(response[3:].strip())
            return None
        except Exception:
            return None

    def reset(self) -> None:
        """Reset the activation graph (clear all edges and counters)."""
        if not self._vault:
            return
        try:
            self._vault._send("GRAPH_RESET")
        except Exception:
            pass

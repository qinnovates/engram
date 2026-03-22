"""Tests for activation graph (Layer 3 + 4).

Tests the co-occurrence tracking and spreading activation via the Rust sidecar.
"""

from __future__ import annotations

import hashlib
import subprocess
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from src.cograph import CoGraph


def _make_hash(seed: int) -> str:
    """Generate a deterministic 64-char hex hash from a seed."""
    return hashlib.sha256(f"artifact-{seed}".encode()).hexdigest()


# ── Unit tests (no sidecar) ──


class TestActivationGraphNoVault:
    """Tests that verify graceful degradation without a sidecar."""

    def test_record_access_no_vault(self):
        g = CoGraph(vault_client=None)
        g.record_access(_make_hash(1))  # Should not raise

    def test_flush_session_no_vault(self):
        g = CoGraph(vault_client=None)
        g.flush_session()  # Should not raise

    def test_get_related_no_vault(self):
        g = CoGraph(vault_client=None)
        result = g.get_related(_make_hash(1))
        assert result == []

    def test_stats_no_vault(self):
        g = CoGraph(vault_client=None)
        assert g.stats() is None

    def test_reset_no_vault(self):
        g = CoGraph(vault_client=None)
        g.reset()  # Should not raise

    def test_record_access_invalid_hash(self):
        g = CoGraph(vault_client=None)
        g.record_access("short")  # Should not raise (ignored)
        g.record_access("")       # Should not raise (ignored)

    def test_get_related_invalid_hash(self):
        g = CoGraph(vault_client=None)
        assert g.get_related("short") == []
        assert g.get_related("") == []


# ── Integration tests (with sidecar mock) ──


class TestActivationGraphWithMock:
    """Tests with a mocked VaultClient that simulates sidecar responses."""

    @pytest.fixture
    def mock_vault(self):
        vault = MagicMock()
        vault._send = MagicMock(return_value="OK")
        return vault

    @pytest.fixture
    def graph(self, mock_vault):
        return CoGraph(vault_client=mock_vault)

    def test_record_access_sends_command(self, graph, mock_vault):
        h = _make_hash(1)
        graph.record_access(h)
        mock_vault._send.assert_called_once_with(f"GRAPH_RECORD {h}")

    def test_flush_session_sends_command(self, graph, mock_vault):
        graph.flush_session()
        mock_vault._send.assert_called_once_with("GRAPH_FLUSH")

    def test_add_keyword_edge_sends_command(self, graph, mock_vault):
        a, b = _make_hash(1), _make_hash(2)
        graph.add_keyword_edge(a, b, 0.35)
        mock_vault._send.assert_called_once_with(
            f"GRAPH_KEYWORD_EDGE {a} {b} 0.3500"
        )

    def test_get_related_parses_json(self, graph, mock_vault):
        h = _make_hash(1)
        mock_vault._send.return_value = (
            'OK [{"hash":"abcd","score":0.8500},{"hash":"efgh","score":0.6200}]'
        )
        results = graph.get_related(h)
        assert len(results) == 2
        assert results[0]["hash"] == "abcd"
        assert results[0]["score"] == 0.85

    def test_get_related_empty_result(self, graph, mock_vault):
        mock_vault._send.return_value = "OK []"
        results = graph.get_related(_make_hash(1))
        assert results == []

    def test_stats_parses_json(self, graph, mock_vault):
        mock_vault._send.return_value = (
            'OK {"nodes":5,"edges":10,"sessions":3,"buffer_size":0,"total_recalls":15}'
        )
        stats = graph.stats()
        assert stats["nodes"] == 5
        assert stats["edges"] == 10
        assert stats["total_recalls"] == 15

    def test_reset_sends_command(self, graph, mock_vault):
        graph.reset()
        mock_vault._send.assert_called_once_with("GRAPH_RESET")

    def test_record_access_handles_error(self, graph, mock_vault):
        mock_vault._send.side_effect = Exception("pipe broken")
        graph.record_access(_make_hash(1))  # Should not raise

    def test_get_related_handles_error(self, graph, mock_vault):
        mock_vault._send.side_effect = Exception("pipe broken")
        results = graph.get_related(_make_hash(1))
        assert results == []


# ── Sidecar integration tests (real binary) ──


def _find_vault_binary() -> str | None:
    """Find the engram-vault binary for integration tests."""
    candidates = [
        Path(__file__).parent.parent / "sidecar" / "target" / "release" / "engram-vault",
        Path(__file__).parent.parent / "sidecar" / "target" / "debug" / "engram-vault",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


@pytest.fixture
def sidecar():
    """Start a real sidecar process for integration testing."""
    binary = _find_vault_binary()
    if not binary:
        pytest.skip("engram-vault binary not found — run `cargo build --release`")

    proc = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def send(cmd: str) -> str:
        proc.stdin.write(cmd + "\n")
        proc.stdin.flush()
        return proc.stdout.readline().strip()

    # Health check
    assert send("PING") == "PONG"

    yield send

    send("QUIT")
    proc.wait(timeout=5)


class TestActivationGraphSidecar:
    """Integration tests against the real Rust sidecar binary."""

    def test_graph_record(self, sidecar):
        h = _make_hash(1)
        assert sidecar(f"GRAPH_RECORD {h}") == "OK"

    def test_graph_flush(self, sidecar):
        assert sidecar("GRAPH_FLUSH") == "OK"

    def test_graph_stats_initial(self, sidecar):
        response = sidecar("GRAPH_STATS")
        assert response.startswith("OK")
        assert '"nodes":0' in response or '"sessions":' in response

    def test_graph_record_and_flush_creates_edges(self, sidecar):
        a, b, c = _make_hash(10), _make_hash(11), _make_hash(12)
        sidecar(f"GRAPH_RECORD {a}")
        sidecar(f"GRAPH_RECORD {b}")
        sidecar(f"GRAPH_RECORD {c}")
        sidecar("GRAPH_FLUSH")

        response = sidecar("GRAPH_STATS")
        assert response.startswith("OK")
        # Should have 3 nodes and 6 directed edges (a→b, b→a, a→c, c→a, b→c, c→b)
        import json
        stats = json.loads(response[3:].strip())
        assert stats["nodes"] == 3
        assert stats["edges"] == 6  # bidirectional edges counted individually
        assert stats["sessions"] == 1

    def test_graph_keyword_edge(self, sidecar):
        a, b = _make_hash(20), _make_hash(21)
        response = sidecar(f"GRAPH_KEYWORD_EDGE {a} {b} 0.4500")
        assert response == "OK"

    def test_graph_activate_with_keyword_edges(self, sidecar):
        a, b, c = _make_hash(30), _make_hash(31), _make_hash(32)
        sidecar(f"GRAPH_KEYWORD_EDGE {a} {b} 0.8000")
        sidecar(f"GRAPH_KEYWORD_EDGE {a} {c} 0.3000")

        response = sidecar(f"GRAPH_ACTIVATE {a} 1 5")
        assert response.startswith("OK")

        import json
        results = json.loads(response[3:].strip())
        assert len(results) == 2
        # b should rank higher
        assert results[0]["score"] > results[1]["score"]

    def test_graph_activate_depth_2(self, sidecar):
        a, b, c = _make_hash(40), _make_hash(41), _make_hash(42)
        # a → b → c chain (no direct a → c)
        sidecar(f"GRAPH_KEYWORD_EDGE {a} {b} 0.9000")
        sidecar(f"GRAPH_KEYWORD_EDGE {b} {c} 0.9000")

        response = sidecar(f"GRAPH_ACTIVATE {a} 2 5")
        assert response.startswith("OK")

        import json
        results = json.loads(response[3:].strip())
        hashes = [r["hash"] for r in results]
        # Should find both b and c
        assert b in hashes
        assert c in hashes

    def test_graph_activate_empty(self, sidecar):
        h = _make_hash(99)
        response = sidecar(f"GRAPH_ACTIVATE {h} 2 3")
        assert response == "OK []"

    def test_graph_reset(self, sidecar):
        a, b = _make_hash(50), _make_hash(51)
        sidecar(f"GRAPH_KEYWORD_EDGE {a} {b} 0.5000")

        sidecar("GRAPH_RESET")

        response = sidecar("GRAPH_STATS")
        import json
        stats = json.loads(response[3:].strip())
        assert stats["nodes"] == 0
        assert stats["edges"] == 0

    def test_graph_record_invalid_hash(self, sidecar):
        response = sidecar("GRAPH_RECORD not_hex")
        assert response.startswith("ERROR")

    def test_graph_record_short_hash(self, sidecar):
        response = sidecar("GRAPH_RECORD abcd")
        assert response.startswith("ERROR")

    def test_graph_corecall_accumulates(self, sidecar):
        a, b = _make_hash(60), _make_hash(61)
        # 5 sessions with both a and b
        for _ in range(5):
            sidecar(f"GRAPH_RECORD {a}")
            sidecar(f"GRAPH_RECORD {b}")
            sidecar("GRAPH_FLUSH")

        stats_resp = sidecar("GRAPH_STATS")
        import json
        stats = json.loads(stats_resp[3:].strip())
        assert stats["sessions"] == 5
        assert stats["nodes"] == 2

    def test_graph_no_self_loops(self, sidecar):
        a = _make_hash(70)
        sidecar(f"GRAPH_RECORD {a}")
        sidecar("GRAPH_FLUSH")

        # Single artifact session should create no edges
        response = sidecar(f"GRAPH_ACTIVATE {a} 1 5")
        assert response == "OK []"

    def test_graph_ppmi_cold_start(self, sidecar):
        """PPMI requires 3+ co-recalls. With only 2, edges exist but weight is 0."""
        a, b = _make_hash(80), _make_hash(81)
        for _ in range(2):
            sidecar(f"GRAPH_RECORD {a}")
            sidecar(f"GRAPH_RECORD {b}")
            sidecar("GRAPH_FLUSH")

        # Activation should return empty or very low scores
        # because PPMI is gated at 3 co-recalls
        response = sidecar(f"GRAPH_ACTIVATE {a} 1 5")
        import json
        results = json.loads(response[3:].strip())
        # Either empty or all scores below threshold
        for r in results:
            assert r["score"] < 0.1

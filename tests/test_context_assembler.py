"""Tests for the SIEMPLE-AI context assembler."""

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from src.context_assembler import ContextAssembler, SessionState, AssembledContext


class TestSessionState:
    """Tests for session TTL and expiry."""

    def test_empty_created_at_is_expired(self) -> None:
        session = SessionState(session_id="test", created_at="")
        assert session.is_expired is True

    def test_recent_session_not_expired(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        session = SessionState(session_id="test", created_at=now)
        assert session.is_expired is False

    def test_old_session_expired(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat()
        session = SessionState(session_id="test", created_at=old)
        assert session.is_expired is True

    def test_boundary_72h_not_expired(self) -> None:
        boundary = (datetime.now(timezone.utc) - timedelta(hours=71)).isoformat()
        session = SessionState(session_id="test", created_at=boundary)
        assert session.is_expired is False


class TestContextAssembler:
    """Tests for context assembly logic."""

    def setup_method(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_dir = Path(self.tmpdir)
        self.hot_dir = self.config_dir / "hot"
        self.hot_dir.mkdir(parents=True)
        self.assembler = ContextAssembler(config_dir=self.config_dir)

    def _write_hot_artifact(self, artifact_id: str, data: dict) -> None:
        path = self.hot_dir / f"{artifact_id}.json"
        path.write_text(json.dumps(data))

    def test_empty_assembly(self) -> None:
        result = self.assembler.assemble(objective="test")
        assert result.facts_injected == 0
        assert result.episodes_injected == 0
        assert result.token_estimate >= 0

    def test_facts_injected(self) -> None:
        self._write_hot_artifact("fact-1", {
            "artifact_id": "fact-1",
            "content": "User prefers Python",
            "source_label": "language_pref",
            "confidence": 1.0,
            "significance": 0.8,
            "sensitivity": "low",
            "memory_type": "preference",
        })
        self._write_hot_artifact("fact-2", {
            "artifact_id": "fact-2",
            "content": "Project uses PostgreSQL",
            "source_label": "database_engine",
            "confidence": 0.9,
            "significance": 0.7,
            "sensitivity": "low",
            "memory_type": "domain_fact",
        })

        result = self.assembler.assemble(objective="database work")
        assert result.facts_injected == 2
        assert "Python" in result.context_text
        assert "PostgreSQL" in result.context_text

    def test_high_sensitivity_excluded_from_bulk(self) -> None:
        self._write_hot_artifact("secret-fact", {
            "artifact_id": "secret-fact",
            "content": "Internal credentials setup",
            "source_label": "internal_creds",
            "confidence": 1.0,
            "significance": 0.9,
            "sensitivity": "high",
            "memory_type": "domain_fact",
        })
        self._write_hot_artifact("normal-fact", {
            "artifact_id": "normal-fact",
            "content": "Sky is blue",
            "source_label": "sky_color",
            "confidence": 1.0,
            "significance": 0.5,
            "sensitivity": "low",
            "memory_type": "domain_fact",
        })

        result = self.assembler.assemble(objective="anything")
        assert result.facts_injected == 1
        assert "Internal credentials" not in result.context_text
        assert "Sky is blue" in result.context_text

    def test_expired_facts_excluded(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._write_hot_artifact("expired-fact", {
            "artifact_id": "expired-fact",
            "content": "Old data that should be gone",
            "source_label": "old_data",
            "confidence": 1.0,
            "significance": 0.5,
            "sensitivity": "low",
            "expires_at": past,
        })

        result = self.assembler.assemble(objective="anything")
        assert result.facts_injected == 0
        assert "Old data" not in result.context_text

    def test_budget_enforcement(self) -> None:
        # Write a large fact
        self._write_hot_artifact("big-fact", {
            "artifact_id": "big-fact",
            "content": "x" * 10000,
            "source_label": "big",
            "confidence": 1.0,
            "significance": 0.5,
            "sensitivity": "low",
        })

        # Tiny budget
        result = self.assembler.assemble(objective="test", budget_tokens=50)
        assert result.token_estimate <= 60  # budget + small overhead for truncation text
        assert "truncated" in result.context_text.lower()

    def test_episodes_injected(self) -> None:
        self._write_hot_artifact("ep-1", {
            "artifact_id": "ep-1",
            "content": "Debugged JWT auth bug",
            "summary": "Debugged JWT auth bug in middleware",
            "source_label": "episode",
            "confidence": 0.9,
            "significance": 0.8,
            "sensitivity": "low",
            "memory_type": "episode",
            "created_date": "2026-04-01",
        })

        result = self.assembler.assemble(objective="auth work")
        assert result.episodes_injected == 1
        assert "JWT" in result.context_text

    def test_layer_merge_with_immutable(self) -> None:
        layers_dir = self.config_dir / "layers"
        layers_dir.mkdir(parents=True)

        # System layer with immutable field
        (layers_dir / "system.json").write_text(json.dumps({
            "safety.pii_redaction": True,
            "response.verbosity": "normal",
        }))

        # User layer tries to override safety
        (layers_dir / "user.json").write_text(json.dumps({
            "safety.pii_redaction": False,  # should be overridden back
            "response.verbosity": "concise",  # should stick
        }))

        result = self.assembler.assemble(objective="test")
        assert "system" in result.layers_merged
        assert "user" in result.layers_merged

    def test_facts_sorted_by_confidence(self) -> None:
        self._write_hot_artifact("low-conf", {
            "artifact_id": "low-conf",
            "content": "Maybe likes tabs",
            "source_label": "tab_pref",
            "confidence": 0.3,
            "significance": 0.3,
            "sensitivity": "low",
        })
        self._write_hot_artifact("high-conf", {
            "artifact_id": "high-conf",
            "content": "Definitely likes spaces",
            "source_label": "space_pref",
            "confidence": 1.0,
            "significance": 0.9,
            "sensitivity": "low",
        })

        result = self.assembler.assemble(objective="formatting")
        # High confidence fact should appear first
        space_pos = result.context_text.find("spaces")
        tab_pos = result.context_text.find("tabs")
        if space_pos >= 0 and tab_pos >= 0:
            assert space_pos < tab_pos


class TestSessionCleanup:
    """Tests for stale session garbage collection."""

    def setup_method(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_dir = Path(self.tmpdir)
        self.sessions_dir = self.config_dir / "sessions"
        self.sessions_dir.mkdir(parents=True)
        self.assembler = ContextAssembler(config_dir=self.config_dir)

    def test_cleanup_expired_session(self) -> None:
        old_time = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        session_file = self.sessions_dir / "old-session.json"
        session_file.write_text(json.dumps({
            "session_id": "old-session",
            "objective": "old work",
            "created_at": old_time,
            "pending_memory_writes": [],
        }))

        cleaned = self.assembler.cleanup_stale_sessions()
        assert "old-session" in cleaned
        assert not session_file.exists()

    def test_keep_active_session(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        session_file = self.sessions_dir / "active-session.json"
        session_file.write_text(json.dumps({
            "session_id": "active-session",
            "objective": "current work",
            "created_at": now,
            "pending_memory_writes": [],
        }))

        cleaned = self.assembler.cleanup_stale_sessions()
        assert len(cleaned) == 0
        assert session_file.exists()

    def test_cleanup_discards_pending_writes(self) -> None:
        old_time = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        session_file = self.sessions_dir / "pending-session.json"
        session_file.write_text(json.dumps({
            "session_id": "pending-session",
            "objective": "had pending work",
            "created_at": old_time,
            "pending_memory_writes": [
                {"content": "unconfirmed fact", "key": "test"},
            ],
        }))

        cleaned = self.assembler.cleanup_stale_sessions()
        assert "pending-session" in cleaned
        assert not session_file.exists()

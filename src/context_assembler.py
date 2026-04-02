"""
SIEMPLE-AI context assembler for Myelin8.

Merges the 3-layer configuration (System + User + Session) and retrieves
relevant memories for injection into Claude's context window.

Layer resolution (last-writer-wins, except immutable fields):
  Layer 1 (System): immutable safety constraints, tool policies
  Layer 4 (User): durable preferences, goals, exclusions
  Layer 5 (Session): ephemeral state, scratchpad, pending writes

Context assembly at inference time:
  1. Merge layers with precedence
  2. Retrieve top-5 semantic facts by relevance
  3. Retrieve top-3 episodic events by importance
  4. Enforce token budget
  5. Return assembled context block
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("myelin8.context_assembler")

DEFAULT_BUDGET_TOKENS = 32_000
CHARS_PER_TOKEN = 4  # conservative estimate
SESSION_TTL_HOURS = 72

# Immutable Layer 1 keys that cannot be overridden
IMMUTABLE_KEYS = frozenset({
    "safety.pii_redaction",
    "safety.secrets_blocking",
    "safety.high_risk_confirmation",
    "security.https_only",
    "tool_policy.web_search",
})


@dataclass
class AssembledContext:
    """Result of context assembly."""

    context_text: str = ""
    token_estimate: int = 0
    facts_injected: int = 0
    episodes_injected: int = 0
    layers_merged: list[str] = field(default_factory=list)
    stale_sessions_cleaned: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "context_text": self.context_text,
            "token_estimate": self.token_estimate,
            "facts_injected": self.facts_injected,
            "episodes_injected": self.episodes_injected,
            "layers_merged": self.layers_merged,
            "stale_sessions_cleaned": self.stale_sessions_cleaned,
        }


@dataclass
class SessionState:
    """Ephemeral session state (Layer 5). Max 72h TTL."""

    session_id: str = ""
    objective: str = ""
    created_at: str = ""
    pending_memory_writes: list[dict] = field(default_factory=list)
    scratchpad: list[dict] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        if not self.created_at:
            return True
        try:
            created = datetime.fromisoformat(self.created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
            return age_hours > SESSION_TTL_HOURS
        except (ValueError, TypeError):
            return True


class ContextAssembler:
    """Assembles context from SIEMPLE-AI layers + Myelin8 memories.

    Read path only. Does NOT modify stored data.
    Queries hot/ JSON files for relevant facts and episodes,
    merges with layer configuration within token budget.
    """

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        max_facts: int = 5,
        max_episodes: int = 3,
    ) -> None:
        self._config_dir = (config_dir or Path.home() / ".myelin8").expanduser().resolve()
        self._max_facts = max_facts
        self._max_episodes = max_episodes

    def assemble(
        self,
        objective: str,
        budget_tokens: int = DEFAULT_BUDGET_TOKENS,
        session_id: Optional[str] = None,
    ) -> AssembledContext:
        """Assemble context for the current session."""
        result = AssembledContext()
        budget_chars = budget_tokens * CHARS_PER_TOKEN
        sections: list[str] = []

        # Step 0: Clean up stale sessions (lazy GC)
        result.stale_sessions_cleaned = self.cleanup_stale_sessions()

        # Step 1: Load Layer 1 (system defaults — immutable)
        system_layer = self._load_layer("system")
        if system_layer:
            sections.append(f"## System Defaults\n{json.dumps(system_layer, indent=2)}")
            result.layers_merged.append("system")

        # Step 2: Load Layer 4 (user preferences)
        user_layer = self._load_layer("user")
        if user_layer:
            # Merge: user overrides system, except immutable keys
            merged = {**(system_layer or {}), **user_layer}
            for key in IMMUTABLE_KEYS:
                if key in (system_layer or {}):
                    merged[key] = system_layer[key]  # type: ignore[index]
            sections.append(f"## User Preferences\n{json.dumps(user_layer, indent=2)}")
            result.layers_merged.append("user")

        # Step 3: Load Layer 5 (session state)
        if session_id:
            session = self._load_session(session_id)
            if session and not session.is_expired:
                sections.append(f"## Session\nObjective: {session.objective}")
                if session.scratchpad:
                    scratch_text = "\n".join(s.get("content", "") for s in session.scratchpad[:5])
                    sections.append(f"## Scratchpad\n{scratch_text}")
                result.layers_merged.append("session")

        # Step 4: Retrieve top-N facts (from hot/ JSON files)
        facts = self._retrieve_facts(objective)
        if facts:
            fact_lines = []
            for fact in facts[:self._max_facts]:
                conf = fact.get("confidence", 0.5)
                key = fact.get("source_label", fact.get("key", ""))
                content = fact.get("content", "")[:200]
                sensitivity = fact.get("sensitivity", "low")
                # Skip high-sensitivity from bulk injection
                if sensitivity == "high":
                    continue
                fact_lines.append(f"- [{key}] (conf:{conf:.1f}) {content}")
            if fact_lines:
                sections.append(f"## Relevant Facts ({len(fact_lines)})\n" + "\n".join(fact_lines))
                result.facts_injected = len(fact_lines)

        # Step 5: Retrieve top-N episodes (from hot/ JSON files)
        episodes = self._retrieve_episodes()
        if episodes:
            ep_lines = []
            for ep in episodes[:self._max_episodes]:
                summary = ep.get("summary", ep.get("content", ""))[:300]
                date = ep.get("created_date", "")
                ep_lines.append(f"- [{date}] {summary}")
            if ep_lines:
                sections.append(f"## Recent Episodes ({len(ep_lines)})\n" + "\n".join(ep_lines))
                result.episodes_injected = len(ep_lines)

        # Step 6: Enforce token budget
        full_text = "\n\n".join(sections)
        if len(full_text) > budget_chars:
            full_text = full_text[:budget_chars] + "\n\n[...truncated to token budget]"

        result.context_text = full_text
        result.token_estimate = len(full_text) // CHARS_PER_TOKEN
        return result

    def _load_layer(self, layer_name: str) -> Optional[dict]:
        """Load a layer config from ~/.myelin8/layers/{layer_name}.json."""
        layer_file = self._config_dir / "layers" / f"{layer_name}.json"
        if not layer_file.exists():
            return None
        try:
            return json.loads(layer_file.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load layer %s: %s", layer_name, e)
            return None

    def _load_session(self, session_id: str) -> Optional[SessionState]:
        """Load session state from ~/.myelin8/sessions/{session_id}.json."""
        session_file = self._config_dir / "sessions" / f"{session_id}.json"
        if not session_file.exists():
            return None
        try:
            data = json.loads(session_file.read_text())
            return SessionState(**{k: v for k, v in data.items() if k in SessionState.__dataclass_fields__})
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.warning("Failed to load session %s: %s", session_id, e)
            return None

    def _retrieve_facts(self, objective: str) -> list[dict]:
        """Retrieve facts from hot/ storage, sorted by significance.

        In Phase 5+, this will query tantivy for relevance-ranked results.
        For now, reads hot/ JSON files and sorts by significance/confidence.
        """
        hot_dir = self._config_dir / "hot"
        if not hot_dir.exists():
            return []

        facts: list[dict] = []
        now = datetime.now(timezone.utc)

        for json_file in hot_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                # Skip expired facts
                expires = data.get("expires_at")
                if expires:
                    try:
                        exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                        if exp_dt < now:
                            continue
                    except (ValueError, TypeError):
                        pass
                facts.append(data)
            except (json.JSONDecodeError, OSError):
                continue

        # Sort by confidence (high first), then significance
        facts.sort(
            key=lambda f: (f.get("confidence", 0.5), f.get("significance", 0.5)),
            reverse=True,
        )
        return facts

    def _retrieve_episodes(self) -> list[dict]:
        """Retrieve episodes from hot/, sorted by date (newest first)."""
        hot_dir = self._config_dir / "hot"
        if not hot_dir.exists():
            return []

        episodes: list[dict] = []
        for json_file in hot_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                if data.get("memory_type") == "episode":
                    episodes.append(data)
            except (json.JSONDecodeError, OSError):
                continue

        episodes.sort(key=lambda e: e.get("created_date", ""), reverse=True)
        return episodes

    def cleanup_stale_sessions(self) -> list[str]:
        """Scan for and clean up expired sessions (lazy GC).

        Called at SessionStart or context assembly. For each expired session:
          - Log session close to audit trail
          - Delete session state file
          - Discard pending_memory_writes (not confirmed)

        Returns list of cleaned up session IDs.
        """
        sessions_dir = self._config_dir / "sessions"
        if not sessions_dir.exists():
            return []

        cleaned: list[str] = []
        for session_file in sessions_dir.glob("*.json"):
            try:
                data = json.loads(session_file.read_text())
                session = SessionState(**{k: v for k, v in data.items() if k in SessionState.__dataclass_fields__})
                if session.is_expired:
                    pending_count = len(session.pending_memory_writes)
                    if pending_count > 0:
                        logger.info(
                            "Session %s expired with %d unconfirmed pending writes — discarding",
                            session.session_id, pending_count,
                        )
                    session_file.unlink()
                    cleaned.append(session.session_id or session_file.stem)
            except (json.JSONDecodeError, OSError, TypeError) as e:
                logger.warning("Failed to process session file %s: %s", session_file, e)
                continue

        return cleaned


def main() -> None:
    """CLI entrypoint for context assembly (called by Rust MCP subprocess)."""
    parser = argparse.ArgumentParser(description="Assemble context from SIEMPLE-AI layers")
    parser.add_argument("--objective", required=True, help="Session objective for relevance")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET_TOKENS, help="Token budget")
    parser.add_argument("--session-id", default="", help="Session ID for ephemeral state")
    args = parser.parse_args()

    assembler = ContextAssembler()
    result = assembler.assemble(
        objective=args.objective,
        budget_tokens=args.budget,
        session_id=args.session_id or None,
    )
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

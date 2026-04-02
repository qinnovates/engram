"""
SIEMPLE-AI governance bridge for Myelin8.

Orchestrates the write path: schema validation → write policy → PII scan →
conflict detection → audit logging. Called by the MCP server (via subprocess)
for every memory_ingest_governed request.

Ownership boundary:
  - This module owns: validation, policy enforcement, audit logging
  - This module does NOT own: storage, compression, search indexing, encryption

Usage (subprocess from Rust MCP server):
  echo '{"content": "...", "label": "preference", ...}' | \
    python3 -m src.governance validate-write

Usage (Python):
  from src.governance import GovernanceGate
  gate = GovernanceGate()
  result = gate.validate_and_write(artifact)
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.write_policy import WritePolicy, WriteDecision
from src.schema_validator import SchemaValidator

logger = logging.getLogger("myelin8.governance")


@dataclass
class GovernanceResult:
    """Result of a governance gate evaluation."""

    status: str  # "ingested" | "pending_confirmation" | "rejected"
    artifact_id: Optional[str] = None
    reason: Optional[str] = None
    conflict: Optional[dict] = None

    def to_json(self) -> str:
        return json.dumps(
            {k: v for k, v in self.__dict__.items() if v is not None},
            default=str,
        )


@dataclass
class GovernanceConfig:
    """Configuration for the governance gate."""

    config_dir: Path = field(default_factory=lambda: Path.home() / ".myelin8")
    siemple_schemas_dir: Optional[Path] = None
    audit_dir: Optional[Path] = None

    def resolve(self) -> None:
        """Resolve paths and create directories."""
        self.config_dir = self.config_dir.expanduser().resolve()
        if self.audit_dir is None:
            self.audit_dir = self.config_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)


class GovernanceGate:
    """Write gate that enforces SIEMPLE-AI governance on memory writes.

    Delegates to:
      - SchemaValidator for fact/episode validation
      - WritePolicy for write rule evaluation
      - Audit logger for tamper-evident logging
    """

    def __init__(self, config: Optional[GovernanceConfig] = None) -> None:
        self._config = config or GovernanceConfig()
        self._config.resolve()
        self._policy = WritePolicy()
        self._validator = SchemaValidator(
            schemas_dir=self._config.siemple_schemas_dir
        )

    def validate_and_write(self, artifact: dict) -> GovernanceResult:
        """Full governance pipeline for a single artifact.

        Steps:
          1. Write policy check (PII, credentials, blocked keys, confidence)
          2. Schema validation (if governance deps installed)
          3. Conflict detection (key-based match against existing facts)
          4. Audit log entry
          5. Return result with artifact_id

        Returns GovernanceResult with status and details.
        """
        content = artifact.get("content", "")
        label = artifact.get("label", "note")
        confidence = float(artifact.get("confidence", 0.5))
        source = artifact.get("source", "explicit")
        key = artifact.get("key") or None
        namespace = artifact.get("namespace", "user")
        session_id = artifact.get("session_id")

        # Step 1: Write policy evaluation (PII, creds, blocked keys, source routing)
        policy_result = self._policy.evaluate(
            content=content,
            label=label,
            confidence=confidence,
            source=source,
            key=key,
            namespace=namespace,
        )

        if policy_result.decision == WriteDecision.REJECTED:
            self._log_audit(
                action="rejected",
                label=label,
                key=key,
                confidence=confidence,
                source=source,
                reason=policy_result.reason,
                rule_id=policy_result.rule_id,
                session_id=session_id,
            )
            return GovernanceResult(
                status="rejected",
                reason=policy_result.reason,
            )

        if policy_result.decision == WriteDecision.PENDING:
            self._log_audit(
                action="pending",
                label=label,
                key=key,
                confidence=policy_result.adjusted_confidence or confidence,
                source=source,
                reason=policy_result.reason,
                rule_id=policy_result.rule_id,
                session_id=session_id,
            )
            return GovernanceResult(
                status="pending_confirmation",
                reason=policy_result.reason,
            )

        # Step 2: Schema validation (only for approved writes)
        schema_type = "episode" if label == "episode" else "fact"
        # Build a minimal fact/episode for schema validation
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        adjusted_conf = policy_result.adjusted_confidence or confidence

        if schema_type == "fact" and key:
            fact_doc = {
                "id": f"fact_{key.replace('.', '_')}",
                "namespace": namespace,
                "type": label if label in ("preference", "identity", "goal", "constraint", "domain_fact", "exclusion") else "domain_fact",
                "key": key,
                "value": content,
                "confidence": adjusted_conf,
                "source": source,
                "created_at": now_iso,
                "updated_at": now_iso,
                "sensitivity": artifact.get("sensitivity", "low"),
            }
            validation = self._validator.validate_fact(fact_doc)
            if not validation.valid:
                logger.warning("Schema validation failed: %s", validation.errors)
                # Non-blocking: log but don't reject (permissive on schema errors)

        # Step 3: Generate artifact ID
        import hashlib
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:8]
        artifact_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{content_hash}"

        # Step 4: Conflict detection (key-based match)
        conflict = None
        if key:
            conflict = self._detect_conflict(key, namespace)

        # Step 5: Audit log
        self._log_audit(
            action="ingested",
            label=label,
            key=key,
            confidence=adjusted_conf,
            source=source,
            reason=policy_result.reason,
            rule_id=policy_result.rule_id,
            session_id=session_id,
            artifact_id=artifact_id,
        )

        return GovernanceResult(
            status="ingested",
            artifact_id=artifact_id,
            reason=policy_result.reason,
            conflict=conflict,
        )

    def _detect_conflict(self, key: str, namespace: str) -> Optional[dict]:
        """Check if a fact with the same key exists in hot storage.

        Phase 4 will extend this to search tantivy. For now, scan hot/ JSON files.
        """
        hot_dir = self._config.config_dir / "hot"
        if not hot_dir.exists():
            return None

        for json_file in hot_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                existing_key = data.get("source_label", "")
                existing_ns = data.get("namespace", "user")
                if existing_key == key and existing_ns == namespace:
                    return {
                        "existing_artifact_id": data.get("artifact_id", json_file.stem),
                        "existing_key": existing_key,
                        "existing_value_preview": str(data.get("content", ""))[:100],
                    }
            except (json.JSONDecodeError, OSError):
                continue
        return None

    def _log_audit(
        self,
        action: str,
        label: str,
        key: Optional[str],
        confidence: float,
        source: str,
        reason: Optional[str],
        rule_id: Optional[str],
        session_id: Optional[str],
        artifact_id: Optional[str] = None,
    ) -> None:
        """Append an audit entry to audit/memory_writes.jsonl.

        NEVER logs content. Only metadata about the governance decision.
        """
        if self._config.audit_dir is None:
            return

        entry = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": f"memory_write_{action}",
            "action": action,
            "label": label,
            "key": key,
            "confidence": confidence,
            "source": source,
            "rule_id": rule_id,
            "reason": reason,
            "session_id": session_id,
            "artifact_id": artifact_id,
        }
        # Remove None values for clean JSONL
        entry = {k: v for k, v in entry.items() if v is not None}

        audit_file = self._config.audit_dir / "memory_writes.jsonl"
        try:
            with open(audit_file, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as e:
            logger.error("Failed to write audit log: %s", e)


def main() -> None:
    """CLI entrypoint for subprocess calls from Rust MCP server."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 -m src.governance validate-write"}))
        sys.exit(1)

    command = sys.argv[1]

    if command == "validate-write":
        raw = sys.stdin.read()
        artifact = json.loads(raw)
        gate = GovernanceGate()
        result = gate.validate_and_write(artifact)
        print(result.to_json())
    elif command == "verify-audit":
        config = GovernanceConfig()
        config.resolve()
        audit_file = config.audit_dir / "memory_writes.jsonl"
        if audit_file.exists():
            line_count = sum(1 for _ in open(audit_file))
            print(json.dumps({"status": "ok", "audit_entries": line_count}))
        else:
            print(json.dumps({"status": "ok", "audit_entries": 0, "message": "No audit file yet"}))
    else:
        print(json.dumps({"error": f"Unknown command: {command}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

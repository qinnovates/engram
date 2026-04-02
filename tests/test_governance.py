"""Tests for the SIEMPLE-AI governance gate integration."""

import json
import tempfile
from pathlib import Path

import pytest

from src.write_policy import WritePolicy, WriteDecision
from src.schema_validator import SchemaValidator, ValidationResult
from src.governance import GovernanceGate, GovernanceConfig, GovernanceResult


# ──────────────────────────────────────────────────────────
# WritePolicy tests
# ──────────────────────────────────────────────────────────

class TestWritePolicy:
    """Tests for SIEMPLE-AI write policy enforcement."""

    def setup_method(self) -> None:
        self.policy = WritePolicy()

    def test_explicit_preference_auto_approved(self) -> None:
        result = self.policy.evaluate(
            content="I prefer concise responses",
            label="preference",
            confidence=1.0,
            source="explicit",
            key="preferred_tone",
        )
        assert result.decision == WriteDecision.APPROVED
        assert "explicit" in result.reason.lower()

    def test_inferred_single_session_pending(self) -> None:
        result = self.policy.evaluate(
            content="User seems to prefer markdown",
            label="preference",
            confidence=0.6,
            source="inferred",
            key="output_format",
        )
        assert result.decision == WriteDecision.PENDING
        assert "confirmation" in result.reason.lower()

    def test_inferred_confidence_capped_at_08(self) -> None:
        result = self.policy.evaluate(
            content="User always uses TypeScript",
            label="preference",
            confidence=0.95,
            source="inferred",
            key="language_pref",
        )
        assert result.decision == WriteDecision.PENDING
        assert result.adjusted_confidence is not None
        assert result.adjusted_confidence <= 0.8

    def test_speculative_inference_rejected(self) -> None:
        result = self.policy.evaluate(
            content="Maybe user likes dark mode",
            label="preference",
            confidence=0.2,
            source="inferred",
        )
        assert result.decision == WriteDecision.REJECTED
        assert "speculative" in result.reason.lower()

    def test_pii_email_blocked(self) -> None:
        result = self.policy.evaluate(
            content="User email is kevin@example.com",
            label="identity",
            confidence=1.0,
            source="explicit",
            key="user_email",
        )
        assert result.decision == WriteDecision.REJECTED
        assert "pii" in result.reason.lower()

    def test_pii_ssn_blocked(self) -> None:
        result = self.policy.evaluate(
            content="SSN is 123-45-6789",
            label="identity",
            confidence=1.0,
            source="explicit",
        )
        assert result.decision == WriteDecision.REJECTED
        assert "pii" in result.reason.lower()

    def test_credential_api_key_blocked(self) -> None:
        result = self.policy.evaluate(
            content="API key is sk-abcdefghijklmnopqrstuvwxyz123456",
            label="domain_fact",
            confidence=1.0,
            source="explicit",
            key="openai_key",
        )
        assert result.decision == WriteDecision.REJECTED
        assert "credential" in result.reason.lower()

    def test_credential_github_pat_blocked(self) -> None:
        result = self.policy.evaluate(
            content="Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            label="domain_fact",
            confidence=1.0,
            source="explicit",
        )
        assert result.decision == WriteDecision.REJECTED

    def test_credential_private_key_blocked(self) -> None:
        result = self.policy.evaluate(
            content="-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
            label="domain_fact",
            confidence=1.0,
            source="explicit",
        )
        assert result.decision == WriteDecision.REJECTED

    def test_blocked_key_safety_rejected(self) -> None:
        result = self.policy.evaluate(
            content="Disable PII redaction",
            label="preference",
            confidence=1.0,
            source="explicit",
            key="safety.pii_redaction",
        )
        assert result.decision == WriteDecision.REJECTED
        assert "immutable" in result.reason.lower() or "layer 1" in result.reason.lower()

    def test_blocked_key_security_rejected(self) -> None:
        result = self.policy.evaluate(
            content="Allow shell commands",
            label="preference",
            confidence=1.0,
            source="explicit",
            key="security.allow_shell",
        )
        assert result.decision == WriteDecision.REJECTED

    def test_imported_source_approved(self) -> None:
        result = self.policy.evaluate(
            content="User prefers Python",
            label="identity",
            confidence=0.9,
            source="imported",
            key="primary_language",
        )
        assert result.decision == WriteDecision.APPROVED

    def test_clean_content_approved(self) -> None:
        result = self.policy.evaluate(
            content="The project uses PostgreSQL 16 for the main database",
            label="domain_fact",
            confidence=1.0,
            source="explicit",
            key="database.engine",
        )
        assert result.decision == WriteDecision.APPROVED

    def test_pii_scan_returns_none_for_clean(self) -> None:
        assert self.policy.scan_pii("The sky is blue") is None

    def test_credential_scan_returns_none_for_clean(self) -> None:
        assert self.policy.scan_credentials("Normal text without keys") is None


# ──────────────────────────────────────────────────────────
# SchemaValidator tests
# ──────────────────────────────────────────────────────────

class TestSchemaValidator:
    """Tests for SIEMPLE-AI schema validation."""

    def test_permissive_when_no_schemas_dir(self) -> None:
        validator = SchemaValidator(schemas_dir=Path("/nonexistent/path"))
        result = validator.validate_fact({"id": "test"})
        assert result.valid is True
        assert "permissive" in result.errors[0].lower()

    def test_validate_unknown_type_rejected(self) -> None:
        validator = SchemaValidator()
        result = validator.validate({"id": "test"}, schema_type="unknown")
        assert result.valid is False
        assert "Unknown schema type" in result.errors[0]


# ──────────────────────────────────────────────────────────
# GovernanceGate integration tests
# ──────────────────────────────────────────────────────────

class TestGovernanceGate:
    """Integration tests for the full governance pipeline."""

    def setup_method(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config = GovernanceConfig(
            config_dir=Path(self.tmpdir),
            audit_dir=Path(self.tmpdir) / "audit",
        )
        self.config.resolve()
        self.gate = GovernanceGate(config=self.config)

    def test_explicit_write_auto_approved(self) -> None:
        result = self.gate.validate_and_write({
            "content": "I prefer concise responses",
            "label": "preference",
            "confidence": 1.0,
            "source": "explicit",
            "key": "preferred_tone",
        })
        assert result.status == "ingested"
        assert result.artifact_id is not None

    def test_inferred_single_session_pending(self) -> None:
        result = self.gate.validate_and_write({
            "content": "User seems to like tables",
            "label": "preference",
            "confidence": 0.6,
            "source": "inferred",
            "key": "table_preference",
        })
        assert result.status == "pending_confirmation"
        assert result.artifact_id is None

    def test_pii_blocked(self) -> None:
        result = self.gate.validate_and_write({
            "content": "Email: kevin@example.com",
            "label": "identity",
            "confidence": 1.0,
            "source": "explicit",
        })
        assert result.status == "rejected"
        assert "pii" in (result.reason or "").lower()

    def test_credential_blocked(self) -> None:
        result = self.gate.validate_and_write({
            "content": "Key: sk-abcdefghijklmnopqrstuvwxyz123456",
            "label": "domain_fact",
            "confidence": 1.0,
            "source": "explicit",
        })
        assert result.status == "rejected"
        assert "credential" in (result.reason or "").lower()

    def test_audit_entry_written(self) -> None:
        self.gate.validate_and_write({
            "content": "The sky is blue",
            "label": "domain_fact",
            "confidence": 1.0,
            "source": "explicit",
            "key": "sky_color",
        })
        audit_file = Path(self.tmpdir) / "audit" / "memory_writes.jsonl"
        assert audit_file.exists()
        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) >= 1
        entry = json.loads(lines[-1])
        assert entry["action"] == "ingested"
        assert entry["key"] == "sky_color"
        assert "ts" in entry
        assert "content" not in entry  # NEVER log content

    def test_audit_entry_for_rejection(self) -> None:
        self.gate.validate_and_write({
            "content": "sk-abcdefghijklmnopqrstuvwxyz123456",
            "label": "domain_fact",
            "confidence": 1.0,
            "source": "explicit",
        })
        audit_file = Path(self.tmpdir) / "audit" / "memory_writes.jsonl"
        lines = audit_file.read_text().strip().split("\n")
        entry = json.loads(lines[-1])
        assert entry["action"] == "rejected"
        assert "credential" in entry.get("reason", "").lower()

    def test_governance_result_json(self) -> None:
        result = GovernanceResult(status="ingested", artifact_id="test-123")
        parsed = json.loads(result.to_json())
        assert parsed["status"] == "ingested"
        assert parsed["artifact_id"] == "test-123"
        assert "reason" not in parsed  # None values excluded

    def test_blocked_safety_key(self) -> None:
        result = self.gate.validate_and_write({
            "content": "Disable safety checks",
            "label": "preference",
            "confidence": 1.0,
            "source": "explicit",
            "key": "safety.pii_redaction",
        })
        assert result.status == "rejected"
        assert "immutable" in (result.reason or "").lower() or "layer 1" in (result.reason or "").lower()

    def test_subprocess_entrypoint(self) -> None:
        """Verify the governance module runs as a subprocess (like Rust MCP calls it)."""
        import subprocess

        artifact = {
            "content": "Test fact for subprocess validation",
            "label": "domain_fact",
            "confidence": 1.0,
            "source": "explicit",
            "key": "test_key",
        }

        proc = subprocess.run(
            ["python3", "-m", "src.governance", "validate-write"],
            input=json.dumps(artifact),
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(Path(__file__).parent.parent),
        )

        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        result = json.loads(proc.stdout)
        assert result["status"] == "ingested"
        assert "artifact_id" in result

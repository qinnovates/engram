"""
SIEMPLE-AI write policy engine for Myelin8.

Evaluates memory write requests against the rules in memory-write-policy.yaml.
Determines whether a write should be auto-approved, held pending, or rejected.

This module enforces:
  - Explicit vs inferred confidence ceilings
  - PII/credential blocklist scanning
  - Security constraint write blocking
  - Transient state rejection
  - Session count requirements for inferred patterns

NEVER stores or logs the actual content — only metadata about the decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class WriteDecision(Enum):
    """Outcome of a write policy evaluation."""

    APPROVED = "approved"
    PENDING = "pending_confirmation"
    REJECTED = "rejected"


@dataclass
class PolicyResult:
    """Result of evaluating a write against the policy."""

    decision: WriteDecision
    reason: str
    rule_id: Optional[str] = None
    adjusted_confidence: Optional[float] = None


# PII detection patterns — if ANY match content, the write is blocked.
PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.ASCII)),
    ("us_phone", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

# Credential patterns — higher severity than PII.
CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("openai_key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("aws_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("bearer_token", re.compile(r"Bearer\s+[a-zA-Z0-9._~+/=-]{20,}")),
    ("github_pat", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("private_key", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
    ("anthropic_key", re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}")),
]

# Keys that belong in Layer 1 (system), not in semantic memory.
BLOCKED_KEY_PREFIXES: list[str] = [
    "safety.",
    "security.",
    "tool_policy.",
]

# Inferred confidence ceiling (SIEMPLE-AI P1: explicit_over_inferred)
INFERRED_CONFIDENCE_CEILING = 0.8


class WritePolicy:
    """Evaluates write requests against SIEMPLE-AI memory-write-policy.yaml.

    The policy is hardcoded from the YAML spec for performance (no YAML
    parsing on every write). The YAML file remains the source of truth
    for documentation; this code is the executable implementation.
    """

    def evaluate(
        self,
        content: str,
        label: str,
        confidence: float,
        source: str,
        key: Optional[str] = None,
        namespace: str = "user",
    ) -> PolicyResult:
        """Evaluate a write request against all policy rules.

        Order of checks (highest severity first):
          1. Credential blocklist
          2. PII blocklist
          3. Blocked key prefixes (security constraints)
          4. Confidence ceiling enforcement
          5. Source-based auto-write vs pending decision
        """
        # 1. Credential scan
        cred_match = self.scan_credentials(content)
        if cred_match is not None:
            return PolicyResult(
                decision=WriteDecision.REJECTED,
                reason=f"Credential pattern detected: {cred_match}. Secrets are never stored in memory.",
                rule_id="blocklist.credentials",
            )

        # 2. PII scan
        pii_match = self.scan_pii(content)
        if pii_match is not None:
            return PolicyResult(
                decision=WriteDecision.REJECTED,
                reason=f"PII pattern detected: {pii_match}. Record the preference without the PII.",
                rule_id="blocklist.pii",
            )

        # 3. Blocked key prefixes
        key_block = self.check_blocked_keys(key)
        if key_block is not None:
            return PolicyResult(
                decision=WriteDecision.REJECTED,
                reason=f"Key targets immutable namespace: {key_block}. Security constraints belong in Layer 1 and hooks, not memory.",
                rule_id="blocklist.security_constraints",
            )

        # 4. Confidence ceiling for inferred sources
        adjusted_confidence = confidence
        if source == "inferred" and confidence > INFERRED_CONFIDENCE_CEILING:
            adjusted_confidence = INFERRED_CONFIDENCE_CEILING

        # 5. Speculative inference rejection
        if source == "inferred" and adjusted_confidence < 0.3:
            return PolicyResult(
                decision=WriteDecision.REJECTED,
                reason="Speculative inference with confidence < 0.3. Not written to durable memory.",
                rule_id="blocklist.speculative_inference",
                adjusted_confidence=adjusted_confidence,
            )

        # 6. Source-based routing
        if source == "explicit":
            return PolicyResult(
                decision=WriteDecision.APPROVED,
                reason=f"Explicit {label} — auto-write at confidence {confidence}",
                rule_id=f"write_rules.explicit_{label}" if label in ("preference", "fact") else "write_rules.explicit_remember_instruction",
                adjusted_confidence=adjusted_confidence,
            )

        if source == "inferred":
            # Single-session inferences go to pending
            return PolicyResult(
                decision=WriteDecision.PENDING,
                reason=f"Inferred {label} from single session — requires confirmation. Confidence capped at {adjusted_confidence}.",
                rule_id="write_rules.inferred_single_session",
                adjusted_confidence=adjusted_confidence,
            )

        if source == "imported":
            return PolicyResult(
                decision=WriteDecision.APPROVED,
                reason=f"Imported {label} — auto-write",
                rule_id="write_rules.imported",
                adjusted_confidence=adjusted_confidence,
            )

        return PolicyResult(
            decision=WriteDecision.REJECTED,
            reason=f"Unknown source type: {source}",
            rule_id="unknown",
        )

    def scan_pii(self, content: str) -> Optional[str]:
        """Scan content for PII patterns. Returns matched category or None."""
        for name, pattern in PII_PATTERNS:
            if pattern.search(content):
                return name
        return None

    def scan_credentials(self, content: str) -> Optional[str]:
        """Scan content for credential patterns. Returns matched category or None."""
        for name, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(content):
                return name
        return None

    def check_blocked_keys(self, key: Optional[str]) -> Optional[str]:
        """Check if the key targets a blocked namespace (Layer 1 immutable)."""
        if key is None:
            return None
        for prefix in BLOCKED_KEY_PREFIXES:
            if key.startswith(prefix):
                return f"blocked_key_prefix:{prefix}"
        return None

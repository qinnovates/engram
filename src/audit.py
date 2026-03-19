"""
Minimal audit logger for Engram operations.

Disabled by default. Engram is a compression tool first — logging is
opt-in for users who need SIEM-grade audit trails.

Logs: timestamp, operation, tier, short artifact hash, outcome.

NEVER logs: file paths, filenames, key sources, query strings,
content, keywords, summaries, usernames, private keys, secrets.

All log lines pass through PII/secret detection before writing.
If a line matches a secret pattern, it is BLOCKED and replaced
with a redaction notice.

Format: one line per event, append-only, 0600 permissions.

Optional: PQ-encrypted syslog output for SIEM forwarding.
Each entry is individually encrypted via the sidecar (ML-KEM-768 +
AES-256-GCM) so log data is protected in transit and at rest,
even on the SIEM.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional


# 10 MB cap — prevents disk fill under adversarial conditions
MAX_AUDIT_BYTES = 10 * 1024 * 1024

# PII and secret detection patterns — if ANY match, the line is blocked.
#
# Grok-equivalent expressions (for SIEM operators who read Logstash syntax):
#
#   %{PEM_KEY}          -----BEGIN .* KEY-----
#   %{SSH_KEY}          ssh-(rsa|ed25519|ecdsa) %{BASE64:key}
#   %{AWS_AKID}         AKIA[0-9A-Z]{16}
#   %{AWS_SECRET}       [0-9a-zA-Z/+=]{40}  (when preceded by aws_secret or similar)
#   %{AZURE_KEY}        [0-9a-zA-Z+/]{86}== (Azure storage/SAS key, base64 64-byte)
#   %{GCP_SA_KEY}       "private_key_id":\s*" (GCP service account JSON)
#   %{API_KEY_OPENAI}   sk-[a-zA-Z0-9]{20,}
#   %{API_KEY_ANTHROPIC} sk-ant-[a-zA-Z0-9]{20,}
#   %{GITHUB_PAT}       ghp_[a-zA-Z0-9]{36,}
#   %{GITHUB_FINE}      github_pat_[a-zA-Z0-9]{22,}
#   %{SLACK_TOKEN}      xox[bpsar]-[0-9a-zA-Z-]{10,}
#   %{EMAIL}            %{NOTSPACE}@%{NOTSPACE}.%{NOTSPACE}
#   %{MACOS_HOME}       /Users/%{USERNAME}/
#   %{LINUX_HOME}       /home/%{USERNAME}/
#   %{SECRET_KEYWORD}   password|passwd|secret|token|credential
#   %{HEX_KEY_MATERIAL} [0-9a-f]{64,}
#
_SECRET_PATTERNS = [
    # Asymmetric keys
    re.compile(r'-----BEGIN .* KEY-----'),                          # PEM keys
    re.compile(r'ssh-(rsa|ed25519|ecdsa)\s+\S{20,}'),             # SSH keys

    # AWS
    re.compile(r'AKIA[0-9A-Z]{16}'),                               # AWS access key ID (AKID)
    re.compile(r'(?i)(aws_secret|secret_access)\S*\s*[=:]\s*\S{20,}'),  # AWS secret key in context

    # Azure
    re.compile(r'[0-9a-zA-Z+/]{86}=='),                            # Azure storage/SAS key (base64)
    re.compile(r'(?i)DefaultEndpointsProtocol='),                   # Azure connection string

    # GCP
    re.compile(r'"private_key_id"\s*:\s*"'),                        # GCP service account JSON
    re.compile(r'"private_key"\s*:\s*"-----BEGIN'),                 # GCP SA private key

    # API keys
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),                            # OpenAI API key
    re.compile(r'sk-ant-[a-zA-Z0-9]{20,}'),                        # Anthropic API key
    re.compile(r'ghp_[a-zA-Z0-9]{36,}'),                           # GitHub PAT (classic)
    re.compile(r'github_pat_[a-zA-Z0-9]{22,}'),                    # GitHub fine-grained PAT
    re.compile(r'xox[bpsar]-[0-9a-zA-Z-]{10,}'),                   # Slack tokens

    # PII
    re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),# Email addresses
    re.compile(r'/Users/[a-zA-Z0-9._-]+/'),                        # macOS home paths
    re.compile(r'/home/[a-zA-Z0-9._-]+/'),                         # Linux home paths
    re.compile(r'C:\\Users\\[a-zA-Z0-9._-]+\\'),                   # Windows home paths

    # Generic secret patterns
    re.compile(r'\b(password|passwd|secret|token|credential)\b',
               re.IGNORECASE),                                      # Secret keywords (word-boundary)
    re.compile(r'[0-9a-f]{64,}'),                                   # Hex key material (64+ chars)
]


def _contains_secret(line: str) -> bool:
    """Check if a log line contains any secret or PII pattern."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(line):
            return True
    return False


_VALID_SYSLOG_TIERS = frozenset({"index", "warm", "cold", "frozen"})


class AuditLogger:
    """Append-only audit logger with PII/secret detection.

    Supports two output modes:
      1. Plaintext local log (audit.log, 0600) — encrypted at rest via engram lock
      2. PQ-encrypted syslog (audit.encf.log) — each entry individually encrypted
         via the sidecar for secure SIEM forwarding
    """

    def __init__(self, log_dir: Path, syslog_config: Optional[dict] = None):
        self.log_path = log_dir / "audit.log"
        self._syslog_path = log_dir / "audit.encf.log" if syslog_config else None
        self._syslog_tier = (syslog_config or {}).get("tier", "index")
        self._syslog_format = (syslog_config or {}).get("format", "json")
        self._syslog_enabled = bool(syslog_config and syslog_config.get("enabled"))
        self._syslog_error_reported = False
        # Validate tier against allowlist — prevents protocol injection via config
        if self._syslog_enabled and self._syslog_tier not in _VALID_SYSLOG_TIERS:
            raise ValueError(
                f"Invalid audit_syslog tier: {self._syslog_tier!r}. "
                f"Must be one of: {sorted(_VALID_SYSLOG_TIERS)}"
            )
        self._ensure_log()

    def _ensure_log(self) -> None:
        """Create log files with restricted permissions if they don't exist."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        for path in [self.log_path, self._syslog_path]:
            if path is None:
                continue
            try:
                fd = os.open(
                    str(path),
                    os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600,
                )
                os.close(fd)
            except FileExistsError:
                pass  # Already exists — no action needed

    def _write(self, line: str, structured: Optional[dict] = None) -> None:
        """Append a line to the audit log. Blocks lines containing secrets/PII."""
        try:
            # PII/secret gate — block any line that matches a secret pattern
            if _contains_secret(line):
                line = f"{self._ts()} REDACTED — log line contained potential secret/PII"
                structured = None  # Don't forward redacted entries

            if self.log_path.exists() and self.log_path.stat().st_size > MAX_AUDIT_BYTES:
                return  # Log full — silently drop. User should rotate.
            with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(line + "\n")

            # PQ-encrypted syslog output
            if self._syslog_enabled and structured is not None:
                self._write_encrypted_syslog(structured)
        except OSError:
            pass  # Audit logging must never break the operation

    def _write_encrypted_syslog(self, entry: dict) -> None:
        """Encrypt a single log entry and append to the encrypted syslog.

        Each entry is individually encrypted with the sidecar using the
        configured tier key (default: index). This means each line in
        audit.encf.log is a standalone .encf blob that can be independently
        decrypted. The SIEM stores encrypted blobs; decryption happens at
        the analyst workstation with proper key access.
        """
        try:
            from .vault import VaultClient

            # Serialize entry to JSON bytes
            entry_bytes = json.dumps(entry, separators=(",", ":")).encode("utf-8")

            # Write to temp file, encrypt via sidecar, read back
            fd, tmp_plain = tempfile.mkstemp(prefix="engram-syslog-", suffix=".json")
            tmp_enc = tmp_plain + ".encf"
            try:
                os.write(fd, entry_bytes)
                os.fchmod(fd, 0o600)
                os.close(fd)

                client = VaultClient()
                try:
                    client.encrypt(Path(tmp_plain), Path(tmp_enc), self._syslog_tier)
                finally:
                    client.close()

                # Read encrypted blob and append as hex line to syslog
                with open(tmp_enc, "rb") as f:
                    encrypted_hex = f.read().hex()

                if self._syslog_path:
                    with open(self._syslog_path, "a", encoding="ascii") as f:
                        f.write(encrypted_hex + "\n")
            finally:
                if os.path.exists(tmp_plain):
                    os.unlink(tmp_plain)
                if os.path.exists(tmp_enc):
                    os.unlink(tmp_enc)
        except Exception as exc:
            # Emit a single warning on first failure so misconfiguration is visible
            if not self._syslog_error_reported:
                import sys
                print(f"engram: syslog encryption failed: {exc}", file=sys.stderr)
                self._syslog_error_reported = True

    def _ts(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _structured(self, operation: str, **fields) -> dict:
        """Build a structured log entry for syslog forwarding."""
        entry = {"ts": self._ts(), "op": operation}
        entry.update(fields)
        return entry

    def tier(self, from_tier: str, to_tier: str,
             artifact_hash: str, ratio: float) -> None:
        """Log a tier transition."""
        h = artifact_hash[:6]
        self._write(
            f"{self._ts()} TIER {from_tier}>{to_tier} {ratio:.1f}x {h}",
            self._structured("tier", from_tier=from_tier, to_tier=to_tier,
                             ratio=round(ratio, 1), hash=h),
        )

    def recall(self, tier: str, artifact_hash: str) -> None:
        """Log an artifact recall to hot tier."""
        h = artifact_hash[:6]
        self._write(
            f"{self._ts()} RECALL {tier} {h}",
            self._structured("recall", tier=tier, hash=h),
        )

    def encrypt(self, tier: str, artifact_hash: str, ok: bool) -> None:
        """Log an encryption event."""
        status = "ok" if ok else "fail"
        h = artifact_hash[:6]
        self._write(
            f"{self._ts()} ENCRYPT {tier} {h} {status}",
            self._structured("encrypt", tier=tier, hash=h, status=status),
        )

    def decrypt(self, tier: str, artifact_hash: str, ok: bool) -> None:
        """Log a decryption event."""
        status = "ok" if ok else "fail"
        h = artifact_hash[:6]
        self._write(
            f"{self._ts()} DECRYPT {tier} {h} {status}",
            self._structured("decrypt", tier=tier, hash=h, status=status),
        )

    def rotate(self, tier: str, old_gen: int, new_gen: int, count: int) -> None:
        """Log a key rotation."""
        self._write(
            f"{self._ts()} ROTATE {tier} gen{old_gen}>{new_gen} {count}headers",
            self._structured("rotate", tier=tier, old_gen=old_gen,
                             new_gen=new_gen, count=count),
        )

    def search(self, result_count: int) -> None:
        """Log a search operation (no query content)."""
        self._write(
            f"{self._ts()} SEARCH {result_count}hits",
            self._structured("search", hits=result_count),
        )

    def error(self, operation: str, short_hash: str = "") -> None:
        """Log an operation failure."""
        h = short_hash[:6] if short_hash else "?"
        self._write(
            f"{self._ts()} ERROR {operation} {h}",
            self._structured("error", failed_op=operation, hash=h),
        )

"""
Python client for engram-vault (Rust sidecar).

This module is the ONLY interface between Python and key operations.
Python NEVER sees private key material. All crypto is delegated to
the compiled engram-vault binary which uses mlock + zeroize.

Protocol: stdin/stdout, one command per line.
  ENCRYPT <input> <output> <tier> → OK | ERROR <msg>
  DECRYPT <input> <output> <tier> → OK | ERROR <msg>
  KEYGEN <tier>                   → OK <pubkey> | ERROR <msg>
  PING                            → PONG
  QUIT                            → BYE
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .encryption import EncryptionError


# Path to the compiled sidecar binary
_VAULT_BINARY_NAME = "engram-vault"

# Allowed tier values — rejects anything else before it hits the protocol
_VALID_TIERS = frozenset({"hot", "warm", "cold", "frozen", "index"})


def _find_vault_binary() -> str:
    """Find and verify the engram-vault binary."""
    candidates = []

    # Check PATH first
    found = shutil.which(_VAULT_BINARY_NAME)
    if found:
        candidates.append(found)

    # Check adjacent to this package (development layout)
    pkg_dir = Path(__file__).parent.parent
    dev_path = pkg_dir / "sidecar" / "target" / "release" / _VAULT_BINARY_NAME
    if dev_path.exists():
        candidates.append(str(dev_path))

    for binary in candidates:
        # Security: verify the binary is not world-writable (CWE-426)
        try:
            stat = os.stat(binary)
            if stat.st_mode & 0o022:  # group- or world-writable
                continue  # Skip — could be tampered
            return binary
        except OSError:
            continue

    raise EncryptionError(
        f"{_VAULT_BINARY_NAME} not found or insecure. Install it:\n"
        f"  cd sidecar && cargo build --release\n"
        f"  cp target/release/{_VAULT_BINARY_NAME} /usr/local/bin/\n"
        f"\n"
        f"The binary must not be group- or world-writable."
    )


class VaultClient:
    """Client for the engram-vault sidecar process.

    Manages a long-lived subprocess. The sidecar stays running for the
    duration of the engine's lifecycle, accepting commands via stdin.
    """

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._binary = _find_vault_binary()

    def _ensure_running(self) -> subprocess.Popen:
        """Start the sidecar if not already running."""
        if self._proc is not None and self._proc.poll() is None:
            return self._proc

        self._proc = subprocess.Popen(
            [self._binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # Discard stderr to prevent pipe deadlock
            text=True,
        )

        # Health check
        response = self._send("PING")
        if response != "PONG":
            raise EncryptionError(
                f"engram-vault health check failed: {response}"
            )

        return self._proc

    def _send(self, command: str) -> str:
        """Send a command to the sidecar and return the response."""
        # Final defense against protocol injection — no caller should pass these,
        # but this catches future mistakes at the lowest level
        if '\n' in command or '\r' in command or '\0' in command:
            raise EncryptionError("Protocol injection blocked: command contains control characters")
        proc = self._ensure_running()
        try:
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
            response = proc.stdout.readline().strip()
            return response
        except (BrokenPipeError, OSError):
            self._proc = None
            raise EncryptionError("engram-vault process died unexpectedly")

    @staticmethod
    def _validate_input(value: str, name: str) -> None:
        """Reject inputs that could inject commands via the line protocol."""
        if "\n" in value or "\r" in value or "\0" in value:
            raise EncryptionError(
                f"Invalid {name} — contains newline or null byte"
            )
        if not value:
            raise EncryptionError(f"Empty {name}")
        # Spaces in paths break the space-delimited protocol
        if name in ("input_path", "output_path") and " " in value:
            raise EncryptionError(
                f"Invalid {name} — paths with spaces are not supported "
                f"in the sidecar protocol. Rename or symlink the file."
            )
        # Tier allowlist — prevents protocol injection via crafted tier values
        if name == "tier" and value not in _VALID_TIERS:
            raise EncryptionError(
                f"Invalid tier: {value!r}. Must be one of: {sorted(_VALID_TIERS)}"
            )

    def encrypt(self, input_path: Path, output_path: Path, tier: str) -> None:
        """Encrypt a file using the tier's public key.

        Public key is retrieved from Keychain by the sidecar.
        No secret material involved on the Python side.
        """
        # Canonicalize paths to prevent traversal (CWE-22)
        input_path = Path(input_path).resolve()
        output_path = Path(output_path).resolve()
        self._validate_input(str(input_path), "input_path")
        self._validate_input(str(output_path), "output_path")
        self._validate_input(tier, "tier")
        response = self._send(
            f"ENCRYPT {input_path} {output_path} {tier}"
        )
        if not response.startswith("OK"):
            raise EncryptionError(
                f"Vault encrypt failed: {response.removeprefix('ERROR ')}"
            )

    def decrypt(self, input_path: Path, output_path: Path, tier: str) -> None:
        """Decrypt a file using the tier's private key.

        Private key is retrieved from Keychain by the sidecar,
        used for in-process ML-KEM + AES-256-GCM decryption,
        then zeroed via Zeroizing<T>. Python never sees it.
        """
        # Canonicalize paths to prevent traversal (CWE-22)
        input_path = Path(input_path).resolve()
        output_path = Path(output_path).resolve()
        self._validate_input(str(input_path), "input_path")
        self._validate_input(str(output_path), "output_path")
        self._validate_input(tier, "tier")
        response = self._send(
            f"DECRYPT {input_path} {output_path} {tier}"
        )
        if not response.startswith("OK"):
            raise EncryptionError(
                f"Vault decrypt failed: {response.removeprefix('ERROR ')}"
            )

    def keygen(self, tier: str) -> str:
        """Generate a new keypair for a tier.

        Private key goes directly into Keychain via Security.framework.
        Returns the public key (safe to store in config).
        Private key NEVER enters Python — not in return values, not
        in logs, not in error messages, not in terminal output.
        """
        self._validate_input(tier, "tier")
        response = self._send(f"KEYGEN {tier}")
        if response.startswith("OK "):
            return response[3:].strip()
        raise EncryptionError(
            f"Vault keygen failed: {response.removeprefix('ERROR ')}"
        )

    # ── Merkle Tree (integrity verification) ──

    def merkle_add(self, sha256_hex: str) -> int:
        """Add a SHA-256 hash as a Merkle leaf. Returns leaf index."""
        if len(sha256_hex) != 64:
            raise EncryptionError("SHA-256 hex must be 64 characters")
        self._validate_input(sha256_hex, "sha256_hex")
        response = self._send(f"MERKLE_ADD {sha256_hex}")
        if response.startswith("OK "):
            return int(response[3:].strip())
        raise EncryptionError(f"Merkle add failed: {response}")

    def merkle_root(self) -> Optional[str]:
        """Get the current Merkle root hash."""
        response = self._send("MERKLE_ROOT")
        if response == "OK empty":
            return None
        if response.startswith("OK "):
            return response[3:].strip()
        raise EncryptionError(f"Merkle root failed: {response}")

    def merkle_proof(self, index: int) -> dict:
        """Generate a Merkle proof for leaf at index. Returns proof dict."""
        response = self._send(f"MERKLE_PROOF {index}")
        if not response.startswith("OK "):
            raise EncryptionError(f"Merkle proof failed: {response}")
        parts = response[3:].strip().split()
        if len(parts) < 5:
            raise EncryptionError(f"Unexpected proof format: {response}")
        return {
            "leaf_hash": parts[0],
            "leaf_index": int(parts[1]),
            "siblings": parts[2].split(",") if parts[2] else [],
            "directions": parts[3].split(",") if parts[3] else [],
            "root": parts[4],
        }

    def merkle_verify(self, proof: dict) -> bool:
        """Verify a Merkle proof. Constant-time in Rust."""
        leaf = proof["leaf_hash"]
        siblings = ",".join(proof["siblings"])
        directions = ",".join(proof["directions"])
        root = proof["root"]
        combined = f"{siblings}|{directions}"
        response = self._send(f"MERKLE_VERIFY {leaf} {combined} {root}")
        if response == "OK true":
            return True
        if response == "OK false":
            return False
        raise EncryptionError(f"Merkle verify failed: {response}")

    def merkle_count(self) -> int:
        """Get the number of leaves in the Merkle tree."""
        response = self._send("MERKLE_COUNT")
        if response.startswith("OK "):
            return int(response[3:].strip())
        raise EncryptionError(f"Merkle count failed: {response}")

    def merkle_reset(self) -> None:
        """Reset the Merkle tree (clear all leaves)."""
        response = self._send("MERKLE_RESET")
        if response != "OK":
            raise EncryptionError(f"Merkle reset failed: {response}")

    def close(self) -> None:
        """Shut down the sidecar process."""
        if self._proc and self._proc.poll() is None:
            try:
                self._send("QUIT")
            except EncryptionError:
                pass
            self._proc.terminate()
            self._proc = None

    def __enter__(self) -> "VaultClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

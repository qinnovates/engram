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


def _find_vault_binary() -> str:
    """Find the engram-vault binary on PATH or in the sidecar directory."""
    # Check PATH first
    found = shutil.which(_VAULT_BINARY_NAME)
    if found:
        return found

    # Check adjacent to this package (development layout)
    pkg_dir = Path(__file__).parent.parent
    dev_path = pkg_dir / "sidecar" / "target" / "release" / _VAULT_BINARY_NAME
    if dev_path.exists():
        return str(dev_path)

    raise EncryptionError(
        f"{_VAULT_BINARY_NAME} not found. Install it:\n"
        f"  cd sidecar && cargo build --release\n"
        f"  cp target/release/{_VAULT_BINARY_NAME} /usr/local/bin/\n"
        f"\n"
        f"The sidecar handles all key operations so private keys\n"
        f"never enter Python's address space."
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
            stderr=subprocess.PIPE,
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
        proc = self._ensure_running()
        try:
            proc.stdin.write(command + "\n")
            proc.stdin.flush()
            response = proc.stdout.readline().strip()
            return response
        except (BrokenPipeError, OSError):
            self._proc = None
            raise EncryptionError("engram-vault process died unexpectedly")

    def encrypt(self, input_path: Path, output_path: Path, tier: str) -> None:
        """Encrypt a file using the tier's public key.

        Public key is retrieved from Keychain by the sidecar.
        No secret material involved on the Python side.
        """
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
        piped to age via stdin, then zeroed. Python never sees it.
        """
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
        Private key never enters Python.
        """
        response = self._send(f"KEYGEN {tier}")
        if response.startswith("OK "):
            return response[3:].strip()
        raise EncryptionError(
            f"Vault keygen failed: {response.removeprefix('ERROR ')}"
        )

    def close(self) -> None:
        """Shut down the sidecar process."""
        if self._proc and self._proc.poll() is None:
            try:
                self._send("QUIT")
            except EncryptionError:
                pass
            self._proc.terminate()
            self._proc = None

    def __del__(self) -> None:
        self.close()

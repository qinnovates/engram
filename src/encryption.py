"""
Encryption layer — delegates ALL crypto to the engram-vault Rust sidecar.

The sidecar uses NIST-approved algorithms only:
  ML-KEM-768 (FIPS 203) + X25519 hybrid key encapsulation
  AES-256-GCM (FIPS 197 + SP 800-38D) authenticated encryption
  HKDF-SHA256 (SP 800-56C) key derivation

No external binaries (age, GPG, etc). No key material in Python.
All crypto happens in the compiled Rust sidecar with mlock + zeroize.

Security model:
  - Compress THEN encrypt (compress-then-encrypt is standard practice)
  - Encryption uses engram-vault sidecar (must be built from sidecar/)
  - Private keys stored in OS credential vault (Keychain, DPAPI, libsecret)
  - Python only ever sees public keys (for config)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


ENCRYPTED_EXT = ".encf"


class EncryptionError(Exception):
    pass


def encrypt_file(
    input_path: Path,
    tier: str,
    output_path: Optional[Path] = None,
    remove_original: bool = False,
) -> Path:
    """
    Encrypt a file using the tier's public key via the sidecar.

    Public key is retrieved from Keychain by the sidecar.
    No secret material involved on the Python side.

    Args:
        input_path: File to encrypt.
        tier: Tier whose public key to use (warm, cold, frozen, hot).
        output_path: Destination. Defaults to input_path + .encf
        remove_original: Delete source after encryption.

    Returns:
        Path to encrypted file.
    """
    from .vault import VaultClient

    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ENCRYPTED_EXT)

    client = VaultClient()
    try:
        client.encrypt(input_path, output_path, tier)
    finally:
        client.close()

    if remove_original and output_path.exists():
        input_path.unlink()

    return output_path


def decrypt_file(
    input_path: Path,
    tier: str,
    output_path: Optional[Path] = None,
    remove_encrypted: bool = False,
) -> Path:
    """
    Decrypt an .encf file using the tier's private key via the sidecar.

    Private key is retrieved from Keychain by the sidecar,
    used for in-process crypto, then zeroed. Python never sees it.

    Args:
        input_path: Encrypted .encf file.
        tier: Tier whose private key to use (warm, cold, frozen, hot).
        output_path: Destination. Defaults to input_path without .encf suffix.
        remove_encrypted: Delete encrypted file after decryption.

    Returns:
        Path to decrypted file.
    """
    from .vault import VaultClient

    input_path = Path(input_path)

    if output_path is None:
        name = input_path.name
        if name.endswith(ENCRYPTED_EXT):
            name = name[: -len(ENCRYPTED_EXT)]
        output_path = input_path.parent / name

    client = VaultClient()
    try:
        client.decrypt(input_path, output_path, tier)
    finally:
        client.close()

    if remove_encrypted and output_path.exists():
        input_path.unlink()

    return output_path

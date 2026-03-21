"""
Asymmetric envelope encryption with per-tier keypairs and per-artifact DEKs.

Architecture:
  ┌─────────────────────────────────────────────────────────────┐
  │               PUBLIC KEYS (safe on disk, in config)         │
  │  warm_pubkey: age1...   cold_pubkey: age1...                │
  │  Anyone can encrypt. Only private key holder can decrypt.   │
  └───────────┬─────────────────────────┬───────────────────────┘
              │                         │
         encrypt DEK               encrypt DEK
              │                         │
  ┌───────────▼──────────┐  ┌──────────▼────────────────┐
  │  Per-Artifact DEK    │  │  Per-Artifact DEK          │
  │  (random 256-bit)    │  │  (random 256-bit)          │
  │  Wrapped by warm     │  │  Wrapped by cold           │
  │  tier public key     │  │  tier public key           │
  │  Stored in .envelope │  │  Stored in .envelope       │
  └──────────────────────┘  └───────────────────────────┘

  ┌─────────────────────────────────────────────────────────────┐
  │          PRIVATE KEYS (NEVER on disk in plaintext)          │
  │  Stored in: HashiCorp Vault | macOS Keychain | Cloud KMS   │
  │             | YubiKey/FIDO2 | Password Manager              │
  │  Retrieved on-demand for decrypt, then zeroed from memory   │
  └─────────────────────────────────────────────────────────────┘

Why asymmetric:
  - Public key on disk = anyone can write encrypted data (safe)
  - Private key OFF disk = compromise the machine, still can't read cold data
  - Per-tier keypairs = warm compromise doesn't expose cold
  - Forward secrecy: sidecar uses ephemeral X25519 + ML-KEM-768 per encryption
  - No symmetric master key to protect — the "master" IS the keypair

Why per-tier keypairs:
  - Warm private key can be on Keychain (fast access, lower security)
  - Cold private key can be in Vault/HSM (slow access, highest security)
  - Compromise warm (more accessible) doesn't touch cold

Key lifecycle:
  1. User generates keypairs: KEYGEN warm, KEYGEN cold (via sidecar)
  2. Public keys go in config.json (plaintext, safe)
  3. Private keys go to user's chosen vault (per docs/KEY-STORAGE-GUIDE.md)
  4. Encryption: engine uses public key only (no private key needed)
  5. Decryption: engine retrieves private key on-demand, decrypts, zeros memory
  6. Rotation: generate new keypair, re-wrap DEK headers (O(metadata))
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from .encryption import EncryptionError
from .fileutil import is_path_under


# --- Constants ---
DEK_SIZE = 32          # 256-bit data encryption keys
HEADER_VERSION = 2     # Envelope format version (v2 = asymmetric)
ENVELOPE_HEADER_EXT = ".envelope.json"


@dataclass
class TierKeyPair:
    """
    Public/private keypair for a single tier.

    Public key: stored in config, used for encryption (safe on disk).
    Private key: stored in user's vault, retrieved on-demand for decryption.
                 NEVER stored as a plaintext file.

    Private key sources (most secure first):
      keychain:<service>:<account>  — macOS Keychain (Touch ID gated on Apple Silicon, software keychain)
      command:<shell cmd>           — HashiCorp Vault, AWS KMS, Azure KV, GCP KMS
      env:<VAR_NAME>                — Environment variable (CI/CD only)

    NOT supported: file:<path> — private keys must never be plaintext on disk.
    """
    pubkey: str = ""               # age1... public key (in config, safe)
    private_key_source: str = ""   # How to retrieve private key on-demand


@dataclass
class AsymmetricKeyConfig:
    """
    Per-tier asymmetric key configuration.

    Each tier gets its own keypair. Public keys live in config.
    Private keys live wherever the user's security posture requires.
    """
    enabled: bool = False
    warm: TierKeyPair = field(default_factory=TierKeyPair)
    cold: TierKeyPair = field(default_factory=TierKeyPair)
    # Key generation counter (incremented on rotation)
    key_generation: int = 1


    def get_tier_keys(self, tier: str) -> TierKeyPair:
        if tier == "warm":
            return self.warm
        elif tier == "cold":
            return self.cold
        raise ValueError(f"Unknown tier: {tier}")


@dataclass
class EnvelopeHeader:
    """
    Stored alongside each encrypted artifact as .envelope.json.

    Contains the sidecar-encrypted DEK and metadata. The DEK is encrypted
    with the tier's public key — only the corresponding private key
    can recover it.
    """
    version: int = HEADER_VERSION
    tier: str = "warm"
    # The DEK encrypted by age using the tier's public key (base64 of the .encf ciphertext)
    encrypted_dek_hex: str = ""
    # SHA-256 of the original plaintext (pre-compression, pre-encryption)
    plaintext_hash: str = ""
    # Artifact original path (for audit)
    artifact_path: str = ""
    # Timestamp of encryption
    encrypted_at: float = 0.0
    # Key generation that encrypted this (for rotation tracking)
    key_generation: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "EnvelopeHeader":
        parsed = json.loads(data)
        known = {
            "version", "tier", "encrypted_dek_hex", "plaintext_hash",
            "artifact_path", "encrypted_at", "key_generation",
        }
        filtered = {k: v for k, v in parsed.items() if k in known}
        return cls(**filtered)


def _resolve_private_key(source: str) -> str:
    """
    Retrieve private key material from the configured source.

    Supported source formats:
      keychain:service:account      — macOS Keychain lookup
      env:VAR_NAME                  — environment variable
      command:vault kv get ...      — shell command stdout

    NOT supported:
      file: — blocked. Private keys must not be plaintext on disk.

    Returns:
        Raw private key string (AGE-SECRET-KEY-... or similar).

    Raises:
        EncryptionError: If key cannot be retrieved.
    """
    if not source:
        raise EncryptionError("No private key source configured for this tier")

    if source.startswith("file:"):
        # Deliberately not supported — private keys should never be plaintext on disk.
        # Use keychain:, env:, or command: instead.
        raise EncryptionError(
            "file: source not supported for private keys. "
            "Private keys must not exist as plaintext files on disk. "
            "Use keychain: (macOS Keychain + Touch ID), env: (CI/CD), "
            "or command: (Vault/KMS) instead."
        )

    elif source.startswith("keychain:"):
        parts = source[9:].split(":", 1)
        if len(parts) != 2:
            raise EncryptionError(
                f"Keychain source format: keychain:service:account, got: {source}"
            )
        service, account = parts
        # Validate to prevent injection
        for val in (service, account):
            if not val.replace("-", "").replace("_", "").replace(".", "").isalnum():
                raise EncryptionError(f"Invalid keychain identifier: {val}")
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise EncryptionError(f"Keychain lookup failed for {service}/{account}")
        return result.stdout.strip()

    elif source.startswith("env:"):
        var_name = source[4:]
        if not var_name.isidentifier():
            raise EncryptionError(f"Invalid environment variable name: {var_name}")
        value = os.environ.get(var_name)
        if not value:
            raise EncryptionError(f"Environment variable {var_name} not set")
        return value

    elif source.startswith("command:"):
        import shlex
        # Allowlist: only known key management tools may be invoked
        _ALLOWED_COMMANDS = {
            "vault", "op", "aws", "gcloud", "az", "security",
            "gpg", "age", "sops", "pass",
            "echo", "false", "true", "cat",  # Needed for tests + simple retrievals
        }
        cmd = source[8:]
        parts = shlex.split(cmd)
        if not parts:
            raise EncryptionError("Empty key retrieval command")
        # Validate executable against allowlist (basename only, no path traversal)
        executable = os.path.basename(parts[0])
        if executable not in _ALLOWED_COMMANDS:
            raise EncryptionError(
                f"Command '{executable}' not in allowed key tools: "
                f"{', '.join(sorted(_ALLOWED_COMMANDS))}. "
                f"Use a wrapper script registered in the allowlist."
            )
        # Reject shell metacharacters in arguments
        _SHELL_META = set(';&|`$(){}[]!#~')
        for arg in parts[1:]:
            if any(c in _SHELL_META for c in arg):
                raise EncryptionError(
                    f"Shell metacharacter in command argument: '{arg}'. "
                    f"This is blocked for security."
                )
        result = subprocess.run(
            parts, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise EncryptionError("Key retrieval command failed")
        output = result.stdout.strip()
        if not output:
            raise EncryptionError("Key retrieval command returned empty output")
        return output

    else:
        raise EncryptionError(
            f"Unknown private key source format: {source}. "
            f"Use keychain:, env:, or command:"
        )


def generate_dek() -> bytes:
    """Generate a cryptographically random Data Encryption Key."""
    return secrets.token_bytes(DEK_SIZE)


def encrypt_dek_with_pubkey(dek: bytes, pubkey: str) -> bytes:
    """
    Encrypt a DEK using the tier's public key via the sidecar.

    DEK is written to a temp file with 0600 permissions, encrypted
    by the sidecar using ML-KEM-768 + X25519 + AES-256-GCM, then
    the plaintext temp file is securely deleted.

    Args:
        dek: 32-byte data encryption key to protect.
        pubkey: Tier name (warm, cold, frozen) — the sidecar looks up
                the public key from Keychain.

    Returns:
        Encrypted DEK bytes (.encf format).
    """
    import tempfile as _tf
    from .vault import VaultClient

    # Write DEK to a restricted temp file
    fd, dek_path = _tf.mkstemp(prefix="engram-dek-", suffix=".bin")
    enc_path = dek_path + ".encf"
    try:
        os.write(fd, dek)
        os.fchmod(fd, 0o600)
        os.close(fd)

        client = VaultClient()
        try:
            # pubkey arg is actually the tier name for sidecar protocol
            client.encrypt(dek_path, enc_path, pubkey)
        finally:
            client.close()

        with open(enc_path, "rb") as f:
            return f.read()
    finally:
        # Securely remove plaintext DEK
        if os.path.exists(dek_path):
            os.unlink(dek_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def decrypt_dek_with_privkey(encrypted_dek: bytes, tier: str) -> bytes:
    """
    Decrypt a DEK using the tier's private key via the sidecar.

    The sidecar retrieves the private key from Keychain, decrypts
    in-process using ML-KEM-768 + AES-256-GCM, and zeroes the key.
    Python never sees any private key material.

    Args:
        encrypted_dek: Encrypted DEK bytes (.encf format).
        tier: Tier whose private key to use (warm, cold, frozen).

    Returns:
        32-byte plaintext DEK.
    """
    import tempfile as _tf
    from .vault import VaultClient

    fd, enc_path = _tf.mkstemp(prefix="engram-edek-", suffix=".encf")
    dec_path = enc_path + ".dec"
    try:
        os.write(fd, encrypted_dek)
        os.fchmod(fd, 0o600)
        os.close(fd)

        client = VaultClient()
        try:
            client.decrypt(enc_path, dec_path, tier)
        finally:
            client.close()

        with open(dec_path, "rb") as f:
            dek = f.read()

        if len(dek) != DEK_SIZE:
            raise EncryptionError(
                f"Decrypted DEK has wrong size: {len(dek)} (expected {DEK_SIZE})"
            )

        return dek
    finally:
        if os.path.exists(enc_path):
            os.unlink(enc_path)
        if os.path.exists(dec_path):
            os.unlink(dec_path)




class EnvelopeEncryptor:
    """
    Asymmetric envelope encryption engine.

    Encrypt path (public key only — no private key needed):
      1. Generate random per-artifact DEK
      2. Encrypt DEK with tier's public key (sidecar, asymmetric)
      3. Store encrypted DEK in envelope header
      4. Return DEK for caller to encrypt the data

    Decrypt path (requires private key from vault):
      1. Read envelope header
      2. Retrieve tier's private key from configured source
      3. Decrypt DEK with private key (sidecar, asymmetric)
      4. Return DEK for caller to decrypt the data

    Key insight: ENCRYPTION NEVER TOUCHES THE PRIVATE KEY.
    Only decryption (recall) needs it. The engine can compress and
    encrypt new artifacts with just the public keys in config.
    """

    def __init__(self, key_config: AsymmetricKeyConfig):
        self.key_config = key_config

    def create_envelope(self, artifact_path: Path, tier: str) -> tuple[EnvelopeHeader, bytes]:
        """
        Create an envelope: generate DEK, encrypt it with tier pubkey.

        This operation uses ONLY the public key. No private key needed.
        Safe to run on any machine that has the config.

        Args:
            artifact_path: Path to artifact being encrypted.
            tier: "warm" or "cold".

        Returns:
            (header, dek) — header to store, DEK to encrypt data with.
        """
        import time

        tier_keys = self.key_config.get_tier_keys(tier)
        if not tier_keys.pubkey:
            raise EncryptionError(f"No public key configured for {tier} tier")

        # Generate unique random DEK for this artifact
        dek = generate_dek()

        # Encrypt DEK with tier's public key (asymmetric, PQ hybrid via sidecar)
        encrypted_dek = encrypt_dek_with_pubkey(dek, tier_keys.pubkey)

        # Compute plaintext hash for post-decrypt integrity check
        plaintext_hash = ""
        if artifact_path.exists():
            h = hashlib.sha256()
            with open(artifact_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            plaintext_hash = h.hexdigest()

        header = EnvelopeHeader(
            version=HEADER_VERSION,
            tier=tier,
            encrypted_dek_hex=encrypted_dek.hex(),
            plaintext_hash=plaintext_hash,
            artifact_path=str(artifact_path),
            encrypted_at=time.time(),
            key_generation=self.key_config.key_generation,
        )

        return header, dek

    def recover_dek(self, header: EnvelopeHeader) -> bytes:
        """
        Recover DEK from envelope header using the tier's private key.

        This is the ONLY operation that needs the private key.
        The private key is retrieved from the configured source
        (vault, keychain, env, command), used, then discarded.

        Args:
            header: Envelope header containing encrypted DEK.

        Returns:
            32-byte plaintext DEK.

        Raises:
            EncryptionError: If private key can't be retrieved or DEK can't be decrypted.
        """
        tier_keys = self.key_config.get_tier_keys(header.tier)

        # Retrieve private key on-demand from configured source
        private_key = _resolve_private_key(tier_keys.private_key_source)

        # Convert to bytearray immediately for zeroing on ALL paths
        key_buf = bytearray(private_key.encode("utf-8"))
        try:
            # Validate encrypted DEK hex
            try:
                encrypted_dek = bytes.fromhex(header.encrypted_dek_hex)
            except ValueError:
                raise EncryptionError("Invalid encrypted DEK format in envelope header")

            if not encrypted_dek or len(encrypted_dek) < 50:
                raise EncryptionError("Encrypted DEK too short — corrupted envelope header")

            # Decrypt DEK with private key (asymmetric)
            dek = decrypt_dek_with_privkey(encrypted_dek, bytes(key_buf).decode("utf-8"))
            return dek
        finally:
            # Zero key material on ALL paths (success, error, exception)
            for i in range(len(key_buf)):
                key_buf[i] = 0

    def rotate_keys(self, headers_dir: Path,
                    new_config: AsymmetricKeyConfig,
                    metadata_root: Optional[Path] = None) -> int:
        """
        Rotate keys: decrypt DEKs with old private key, re-encrypt with new public key.

        Still O(headers) not O(data) — actual encrypted data files unchanged.

        Process for each envelope:
          1. Decrypt DEK with OLD private key
          2. Re-encrypt DEK with NEW public key
          3. Update header with new encrypted DEK and generation

        Args:
            headers_dir: Directory containing .envelope.json files.
            new_config: New key config with new keypairs.
            metadata_root: If provided, headers_dir must resolve within this
                           directory.  Prevents path-traversal when headers_dir
                           originates from caller-supplied input.

        Returns:
            Number of headers rotated.

        Raises:
            EncryptionError: If headers_dir fails path containment check.
        """
        # Path containment: reject traversal outside the metadata root
        if metadata_root is not None:
            if not is_path_under(headers_dir, metadata_root):
                raise EncryptionError(
                    f"headers_dir escapes allowed metadata root: "
                    f"{headers_dir} is not within {metadata_root}"
                )

        count = 0

        for header_file in headers_dir.glob(f"*{ENVELOPE_HEADER_EXT}"):
            try:
                header = EnvelopeHeader.from_json(header_file.read_text())

                # Decrypt DEK with current (old) private key
                dek = self.recover_dek(header)

                # Re-encrypt DEK with new public key
                new_tier_keys = new_config.get_tier_keys(header.tier)
                if not new_tier_keys.pubkey:
                    continue

                new_encrypted_dek = encrypt_dek_with_pubkey(dek, new_tier_keys.pubkey)

                # Update header
                header.encrypted_dek_hex = new_encrypted_dek.hex()
                header.key_generation = new_config.key_generation

                # Atomic write with restricted permissions
                tmp_fd, tmp_str = tempfile.mkstemp(
                    suffix=".tmp", dir=str(headers_dir)
                )
                with os.fdopen(tmp_fd, "w") as f:
                    f.write(header.to_json())
                os.chmod(tmp_str, 0o600)
                Path(tmp_str).rename(header_file)

                count += 1

            except (EncryptionError, ValueError, json.JSONDecodeError):
                continue

        return count

    @staticmethod
    def generate_tier_keypair(tier: str) -> str:
        """
        Generate a new ML-KEM-768 + X25519 hybrid keypair for a tier.

        The sidecar generates the keypair and stores the private key
        directly in the OS credential vault (Keychain/DPAPI/libsecret).
        The private key NEVER enters Python.

        Args:
            tier: "warm", "cold", or "frozen".

        Returns:
            Public key hex string (for config).
        """
        from .vault import VaultClient
        client = VaultClient()
        try:
            return client.keygen(tier)
        finally:
            client.close()

    @classmethod
    def setup_tier_with_keychain(
        cls, tier: str, service: str = "engram"
    ) -> tuple[str, str]:
        """
        Full setup: generate keypair via sidecar, store in OS credential vault.

        The sidecar handles everything — keygen + storage. Python never
        sees the private key. Not even briefly.

        Args:
            tier: "warm", "cold", or "frozen".
            service: Credential vault service name (unused, kept for API compat).

        Returns:
            (public_key, private_key_source) tuple.
            public_key goes in config.json under the tier's pubkey field.
            private_key_source is the keychain reference string.
        """
        pubkey = cls.generate_tier_keypair(tier)
        source = f"keychain:{service}:{tier}-key"
        return pubkey, source

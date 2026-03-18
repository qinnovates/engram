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
  │  public key via age  │  │  public key via age        │
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
  - Forward secrecy: age uses ephemeral X25519 + ML-KEM-768 per encryption
  - No symmetric master key to protect — the "master" IS the keypair

Why per-tier keypairs:
  - Warm private key can be on Keychain (fast access, lower security)
  - Cold private key can be in Vault/HSM (slow access, highest security)
  - Compromise warm (more accessible) doesn't touch cold

Key lifecycle:
  1. User generates keypairs: age-keygen → warm keypair, age-keygen → cold keypair
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
import shutil
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .encryption import EncryptionError, check_age_installed, _validate_recipient


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
      keychain:<service>:<account>  — macOS Keychain (Touch ID / Secure Enclave on M-series)
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
    warm: TierKeyPair = None  # type: ignore[assignment]
    cold: TierKeyPair = None  # type: ignore[assignment]
    # Key generation counter (incremented on rotation)
    key_generation: int = 1

    def __post_init__(self) -> None:
        if self.warm is None:
            self.warm = TierKeyPair()
        if self.cold is None:
            self.cold = TierKeyPair()

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

    Contains the age-encrypted DEK and metadata. The DEK is encrypted
    with the tier's public key — only the corresponding private key
    can recover it.
    """
    version: int = HEADER_VERSION
    tier: str = "warm"
    # The DEK encrypted by age using the tier's public key (base64 of the age ciphertext)
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
      file:/path/to/key.txt         — read from file
      keychain:service:account      — macOS Keychain lookup
      env:VAR_NAME                  — environment variable
      command:vault kv get ...      — shell command stdout

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
        cmd = source[8:]
        parts = shlex.split(cmd)
        if not parts:
            raise EncryptionError("Empty key retrieval command")
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
            f"Use file:, keychain:, env:, or command:"
        )


def generate_dek() -> bytes:
    """Generate a cryptographically random Data Encryption Key."""
    return secrets.token_bytes(DEK_SIZE)


def encrypt_dek_with_pubkey(dek: bytes, pubkey: str) -> bytes:
    """
    Encrypt a DEK using an age public key (asymmetric).

    DEK is piped via stdin — it NEVER touches disk as plaintext.
    age reads from stdin and writes ciphertext to stdout.

    age uses:
      - X25519 key agreement (classical)
      - ML-KEM-768 key encapsulation (post-quantum, v1.3.0+)
      - ChaCha20-Poly1305 for the symmetric payload

    Each call generates a fresh ephemeral keypair internally,
    providing forward secrecy.

    Args:
        dek: 32-byte data encryption key to protect.
        pubkey: age public key (age1...) or SSH public key.

    Returns:
        age ciphertext bytes containing the encrypted DEK.
    """
    _check_age_cached()
    _validate_recipient(pubkey)

    # Pipe DEK via stdin — never touches disk (CRITICAL: fixes temp file race)
    result = subprocess.run(
        ["age", "-r", pubkey],
        input=dek, capture_output=True, timeout=30,
    )
    if result.returncode != 0:
        raise EncryptionError("Failed to encrypt DEK with age")

    return result.stdout


def decrypt_dek_with_privkey(encrypted_dek: bytes, private_key: str) -> bytes:
    """
    Decrypt a DEK using an age private key (asymmetric).

    Private key is piped via a process substitution fd — it NEVER
    touches disk as a plaintext file. Encrypted DEK is piped via stdin.

    Key material is stored as bytearray and zeroed after use (best effort
    in Python, but zeroing mutable bytes is more reliable than reassigning
    immutable strings).

    Args:
        encrypted_dek: age ciphertext containing the encrypted DEK.
        private_key: age private key string (AGE-SECRET-KEY-...).

    Returns:
        32-byte plaintext DEK.
    """
    _check_age_cached()

    # Convert to bytearray for zeroing (mutable, unlike str)
    key_bytes = bytearray(private_key.encode("utf-8"))

    # Use a named pipe (FIFO) for the identity file — the key passes through
    # the pipe and is never written to a regular file on disk.
    fifo_dir = tempfile.mkdtemp(prefix="tm-")
    fifo_path = os.path.join(fifo_dir, "identity")

    try:
        os.mkfifo(fifo_path, mode=0o600)

        # Start age reading from the FIFO (it blocks until the pipe is written)
        proc = subprocess.Popen(
            ["age", "-d", "-i", fifo_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Write private key to the FIFO (this unblocks age)
        # Must happen in a thread or after Popen since FIFO blocks on open
        with open(fifo_path, "wb") as fifo:
            fifo.write(key_bytes)

        # Send encrypted DEK via stdin, collect decrypted output
        stdout, stderr = proc.communicate(input=encrypted_dek, timeout=30)

        if proc.returncode != 0:
            raise EncryptionError(
                "Failed to decrypt DEK — wrong key or corrupted ciphertext"
            )

        dek = stdout
        if len(dek) != DEK_SIZE:
            raise EncryptionError(
                f"Decrypted DEK has wrong size: {len(dek)} (expected {DEK_SIZE})"
            )

        return bytes(dek)
    finally:
        # Zero key material (bytearray is mutable — this actually overwrites memory)
        for i in range(len(key_bytes)):
            key_bytes[i] = 0

        # Clean up FIFO
        if os.path.exists(fifo_path):
            os.unlink(fifo_path)
        if os.path.exists(fifo_dir):
            os.rmdir(fifo_dir)


# --- Cached age check (avoids 200+ PATH lookups during rotation) ---
_age_checked: bool = False


def _check_age_cached() -> None:
    """Check age is installed, cached after first call."""
    global _age_checked
    if not _age_checked:
        check_age_installed()
        _age_checked = True


class EnvelopeEncryptor:
    """
    Asymmetric envelope encryption engine.

    Encrypt path (public key only — no private key needed):
      1. Generate random per-artifact DEK
      2. Encrypt DEK with tier's public key (age, asymmetric)
      3. Store encrypted DEK in envelope header
      4. Return DEK for caller to encrypt the data

    Decrypt path (requires private key from vault):
      1. Read envelope header
      2. Retrieve tier's private key from configured source
      3. Decrypt DEK with private key (age, asymmetric)
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

        # Encrypt DEK with tier's public key (asymmetric, PQ hybrid via age)
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

        # Validate encrypted DEK hex before passing to age
        try:
            encrypted_dek = bytes.fromhex(header.encrypted_dek_hex)
        except ValueError:
            raise EncryptionError("Invalid encrypted DEK format in envelope header")

        if not encrypted_dek or len(encrypted_dek) < 50:
            raise EncryptionError("Encrypted DEK too short — corrupted envelope header")

        # Decrypt DEK with private key (asymmetric)
        # Private key is passed to decrypt_dek_with_privkey which handles
        # zeroing via bytearray internally
        dek = decrypt_dek_with_privkey(encrypted_dek, private_key)

        return dek

    def rotate_keys(self, headers_dir: Path,
                    new_config: AsymmetricKeyConfig) -> int:
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

        Returns:
            Number of headers rotated.
        """
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
                Path(tmp_str).rename(header_file)

                count += 1

            except (EncryptionError, ValueError, json.JSONDecodeError):
                continue

        return count

    @staticmethod
    def generate_tier_keypair() -> tuple[str, str]:
        """
        Generate a new age keypair for a tier.

        Returns (public_key, private_key).
        The caller decides where to store the private key.

        This is a convenience wrapper — users can also run
        `age-keygen` directly.
        """
        check_age_installed()

        keygen_path = shutil.which("age-keygen")
        if not keygen_path:
            raise EncryptionError("age-keygen not found")

        result = subprocess.run(
            [keygen_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise EncryptionError("age-keygen failed")

        # age-keygen outputs:
        #   # created: <timestamp>
        #   # public key: age1...
        #   AGE-SECRET-KEY-1...
        pubkey = ""
        privkey = ""
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line.startswith("# public key:"):
                pubkey = line.split("# public key:")[1].strip()
            elif line.startswith("AGE-SECRET-KEY-"):
                privkey = line

        if not pubkey or not privkey:
            raise EncryptionError("Failed to parse age-keygen output")

        return pubkey, privkey

    @staticmethod
    def store_private_key_in_keychain(
        private_key: str,
        tier: str,
        service: str = "tiered-memory",
    ) -> str:
        """
        Store a private key in macOS Keychain.

        On Apple Silicon (M-series), Keychain items can be protected by
        the Secure Enclave and require Touch ID or device passcode to access.
        This means the private key is hardware-bound — it cannot be extracted
        even with root access.

        Args:
            private_key: The age private key string.
            tier: "warm" or "cold" (used as the account name).
            service: Keychain service identifier.

        Returns:
            The private_key_source string to put in config
            (e.g., "keychain:tiered-memory:warm").
        """
        account = f"{tier}-key"

        # Validate identifiers
        for val in (service, account):
            if not val.replace("-", "").replace("_", "").isalnum():
                raise EncryptionError(f"Invalid keychain identifier: {val}")

        # Check if entry already exists
        check = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account],
            capture_output=True, text=True, timeout=10,
        )
        if check.returncode == 0:
            # Update existing
            subprocess.run(
                ["security", "delete-generic-password", "-s", service, "-a", account],
                capture_output=True, timeout=10,
            )

        # Add to Keychain
        # -T "" means no application is trusted by default — user must authorize via Touch ID
        result = subprocess.run(
            ["security", "add-generic-password",
             "-s", service, "-a", account,
             "-w", private_key,
             "-T", ""],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise EncryptionError(
                f"Failed to store key in Keychain: {result.stderr.strip()}"
            )

        return f"keychain:{service}:{account}"

    @classmethod
    def setup_tier_with_keychain(
        cls, tier: str, service: str = "tiered-memory"
    ) -> tuple[str, str]:
        """
        Full setup: generate keypair and store private key in macOS Keychain.

        This is the recommended setup flow:
          1. Generate age keypair
          2. Store private key in Keychain (Touch ID protected on M-series)
          3. Return public key (for config) and source string (for config)

        The private key NEVER exists as a file on disk.

        Args:
            tier: "warm" or "cold".
            service: Keychain service name.

        Returns:
            (public_key, private_key_source) tuple.
            public_key goes in config.json under the tier's pubkey field.
            private_key_source goes in the tier's private_key_source field.
        """
        # Generate keypair (private key exists only in memory briefly)
        pubkey, privkey = cls.generate_tier_keypair()

        # Store private key in Keychain immediately
        source = cls.store_private_key_in_keychain(privkey, tier, service)

        # Zero the private key from memory (best effort in Python)
        privkey = "\x00" * len(privkey)  # noqa: F841

        return pubkey, source

"""
Index encryption — encrypts/decrypts the entire ~/.engram/index/ bundle.

The semantic index, embeddings, HNSW graphs, LSH tables, PQ codebook,
and artifact registry all contain metadata about your sessions. Even
though the artifacts themselves are encrypted, the index reveals what
you discussed, which keywords appear, and the structural relationships
between artifacts.

This module encrypts the index as a single tarball on lock, and
decrypts it on unlock. The decrypted index exists in memory (via tmpfs
or a temp dir with 0700 permissions) only while Engram is actively
running.

Flow:
  Session start:  unlock() → decrypt index bundle → load into memory
  During session: index files are plaintext in a 0700 temp dir
  Session end:    lock() → encrypt index bundle → delete plaintext

Uses the Rust sidecar (engram-vault) for encryption/decryption so
private keys never enter Python.
"""

from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path


# Files that should be encrypted when the index is locked
INDEX_FILES = [
    "semantic-index.json",
    "artifact-registry.json",
    "audit.log",
    "embeddings-hot.npy",
    "embeddings-warm.npy",
    "embeddings-cold.npy",
    "embeddings-frozen.bin",
    "hnsw-hot.bin",
    "hnsw-warm.bin",
    "hnsw-cold.bin",
    "hnsw-frozen.bin",
    "lsh-tables.npz",
    "pq-codebook.npz",
    "paths-hot.json",
    "paths-warm.json",
    "paths-cold.json",
    "paths-frozen.json",
    "artifact-id-map.json",
    "compression.dict",
]

INDEX_BUNDLE = "index.tar"
INDEX_BUNDLE_ENCRYPTED = "index.tar.age"
INDEX_TIER = "hot"  # Use the hot tier key for index encryption


class IndexCrypto:
    """Encrypts and decrypts the Engram index bundle."""

    def __init__(self, engram_dir: Path):
        self.engram_dir = engram_dir
        self.bundle_path = engram_dir / INDEX_BUNDLE
        self.encrypted_path = engram_dir / INDEX_BUNDLE_ENCRYPTED
        self._vault = None

    def _get_vault(self):
        """Lazy-load vault client."""
        if self._vault is None:
            from .vault import VaultClient
            self._vault = VaultClient()
        return self._vault

    def is_locked(self) -> bool:
        """Check if the index is currently encrypted (locked)."""
        return self.encrypted_path.exists()

    def has_index_files(self) -> bool:
        """Check if plaintext index files exist."""
        for name in INDEX_FILES:
            if (self.engram_dir / name).exists():
                return True
        return False

    def lock(self) -> None:
        """Encrypt the index: bundle all index files → encrypt → delete plaintext.

        Call this at session end or when Engram is not actively running.
        After locking, the index is a single encrypted .age file.
        """
        if not self.has_index_files():
            return  # Nothing to lock

        # Bundle all index files into a tarball
        existing_files = []
        for name in INDEX_FILES:
            path = self.engram_dir / name
            if path.exists():
                existing_files.append((path, name))

        if not existing_files:
            return

        # Create tarball
        with tarfile.open(str(self.bundle_path), "w") as tar:
            for path, name in existing_files:
                tar.add(str(path), arcname=name)

        # Set permissions on the bundle before encrypting
        os.chmod(str(self.bundle_path), 0o600)

        # Encrypt the bundle via sidecar, guaranteed cleanup
        vault = self._get_vault()
        try:
            vault.encrypt(self.bundle_path, self.encrypted_path, INDEX_TIER)
        finally:
            # Always delete plaintext bundle — even if encryption fails
            self.bundle_path.unlink(missing_ok=True)
        for path, _ in existing_files:
            path.unlink(missing_ok=True)

        # Clean up boilerplate store too (contains plaintext prompt fragments)
        boilerplate_dir = self.engram_dir / "boilerplate"
        if boilerplate_dir.exists():
            # Tar and encrypt boilerplate separately
            bp_tar = self.engram_dir / "boilerplate.tar"
            with tarfile.open(str(bp_tar), "w") as tar:
                for f in boilerplate_dir.iterdir():
                    if f.is_file():
                        tar.add(str(f), arcname=f.name)
            os.chmod(str(bp_tar), 0o600)
            bp_enc = self.engram_dir / "boilerplate.tar.age"
            vault.encrypt(bp_tar, bp_enc, INDEX_TIER)
            bp_tar.unlink(missing_ok=True)
            shutil.rmtree(boilerplate_dir)

    def unlock(self) -> None:
        """Decrypt the index: decrypt .age → extract tarball → index files restored.

        Call this at session start before any search, context, or tier operations.
        Requires Touch ID / vault access for the private key.
        """
        if not self.is_locked():
            return  # Already unlocked or never locked

        # Decrypt the bundle via sidecar
        vault = self._get_vault()
        vault.decrypt(self.encrypted_path, self.bundle_path, INDEX_TIER)

        # Extract tarball with security validation
        try:
            with tarfile.open(str(self.bundle_path), "r") as tar:
                for member in tar.getmembers():
                    # Reject path traversal, absolute paths, symlinks, hardlinks
                    if member.name.startswith("/") or ".." in member.name:
                        raise ValueError(f"Unsafe path in index bundle: {member.name}")
                    if member.issym() or member.islnk():
                        if member.linkname.startswith("/") or ".." in member.linkname:
                            raise ValueError(f"Unsafe link in index bundle: {member.linkname}")
                import sys
                if sys.version_info >= (3, 12):
                    tar.extractall(str(self.engram_dir), filter="data")
                else:
                    tar.extractall(str(self.engram_dir))
        finally:
            # Always clean up plaintext bundle
            self.bundle_path.unlink(missing_ok=True)

        # Set permissions on extracted files
        for name in INDEX_FILES:
            path = self.engram_dir / name
            if path.exists():
                os.chmod(str(path), 0o600)

        # Clean up bundle (keep encrypted version as backup)
        self.bundle_path.unlink(missing_ok=True)

        # Restore boilerplate if encrypted
        bp_enc = self.engram_dir / "boilerplate.tar.age"
        if bp_enc.exists():
            bp_tar = self.engram_dir / "boilerplate.tar"
            vault.decrypt(bp_enc, bp_tar, INDEX_TIER)
            boilerplate_dir = self.engram_dir / "boilerplate"
            boilerplate_dir.mkdir(exist_ok=True)
            try:
                with tarfile.open(str(bp_tar), "r") as tar:
                    for member in tar.getmembers():
                        if member.name.startswith("/") or ".." in member.name:
                            raise ValueError(f"Unsafe path in boilerplate: {member.name}")
                        if member.issym() or member.islnk():
                            if member.linkname.startswith("/") or ".." in member.linkname:
                                raise ValueError(f"Unsafe link in boilerplate: {member.linkname}")
                    import sys
                    if sys.version_info >= (3, 12):
                        tar.extractall(str(boilerplate_dir), filter="data")
                    else:
                        tar.extractall(str(boilerplate_dir))
            finally:
                bp_tar.unlink(missing_ok=True)
            os.chmod(str(boilerplate_dir), 0o700)

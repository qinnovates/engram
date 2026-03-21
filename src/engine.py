"""
Core tiering engine — orchestrates scan, tier evaluation, compression, and encryption.

Lifecycle modeled after Splunk SmartStore + Elasticsearch ILM:

  1. SCAN:  Discover artifacts across configured targets
  2. EVALUATE: Check age + idle time against tier policy thresholds
  3. TIER:  Compress (and optionally encrypt) eligible artifacts
  4. TRACK: Update metadata registry with new state

Transition flow:
  HOT (uncompressed) -> WARM (zstd -3) -> COLD (zstd -9, recompressed)

Access-based promotion (cold -> hot on read):
  When a cold artifact is accessed, it's decompressed back to hot tier.
  This matches Splunk SmartStore's cache-on-read behavior.
"""

from __future__ import annotations

import os
from pathlib import Path

import zstandard as zstd
from typing import Optional

from .config import EngineConfig
from .metadata import MetadataStore, Tier, ArtifactMeta, compute_sha256
from .compressor import decompress_file
from .pipeline import CompressionPipeline
from .encryption import EncryptionError
from .context import SemanticIndex, ContextBuilder, ContextBudget, DEFAULT_CONTEXT_BUDGET_CHARS


class EngineError(Exception):
    """Base exception for all engine errors."""
    pass


class IntegrityError(EngineError):
    """Raised when SHA-256 verification fails on recall or compression."""
    pass


class PathContainmentError(EngineError):
    """Raised when a path escapes allowed directories."""
    pass


class RecallError(EngineError):
    """Raised when an artifact cannot be recalled from a compressed tier."""
    def __init__(self, message: str, tier: str = "", path: str = ""):
        self.tier = tier
        self.artifact_path = path
        super().__init__(message)


class ArtifactNotFoundError(RecallError):
    """The compressed artifact file is missing from disk."""
    pass


class DecompressionError(RecallError):
    """Decompression failed (corrupted zst, missing dictionary, bad Parquet)."""
    pass


class DecryptionRequiredError(RecallError):
    """Artifact is encrypted but no key source is configured or accessible."""
    pass


class TierAction:
    """Record of a tiering action taken."""
    def __init__(self, path: str, from_tier: str, to_tier: str,
                 original_size: int = 0, new_size: int = 0,
                 ratio: float = 1.0, encrypted: bool = False,
                 dry_run: bool = False):
        self.path = path
        self.from_tier = from_tier
        self.to_tier = to_tier
        self.original_size = original_size
        self.new_size = new_size
        self.ratio = ratio
        self.encrypted = encrypted
        self.dry_run = dry_run

    def __repr__(self) -> str:
        prefix = "[DRY RUN] " if self.dry_run else ""
        enc = " +encrypted" if self.encrypted else ""
        return (
            f"{prefix}{self.from_tier} -> {self.to_tier}: "
            f"{self.path} ({self.ratio}x{enc})"
        )


def _is_within_scan_targets(path: Path, config: EngineConfig) -> bool:
    """Check if a path is within at least one configured scan target."""
    resolved = path.resolve()
    for target in config.scan_targets:
        target_root = target.resolve().resolve()
        try:
            resolved.relative_to(target_root)
            return True
        except ValueError:
            continue
    return False


def _validate_registry_path(path_str: str, config: EngineConfig, field_name: str) -> Path:
    """Validate that a path from the registry is within allowed directories."""
    p = Path(path_str).resolve()
    if not _is_within_scan_targets(p, config):
        # Also allow paths within metadata_dir (compressed files live there or alongside originals)
        meta_dir = config.resolve_metadata_dir()
        try:
            p.relative_to(meta_dir)
            return p
        except ValueError:
            pass
        # Allow paths in scan target directories (compressed files sit next to originals)
        for target in config.scan_targets:
            target_root = target.resolve().resolve()
            try:
                p.relative_to(target_root)
                return p
            except ValueError:
                continue
        raise PathContainmentError(
            f"Registry {field_name} escapes allowed directories: {path_str}"
        )
    return p


class TieringEngine:
    """Main engine that orchestrates tiered memory management."""

    def __init__(self, config: EngineConfig):
        self.config = config
        meta_dir = config.resolve_metadata_dir()

        # Index encryption — unlock before loading any index files
        self._index_crypto = None
        if config.encryption.enabled:
            from .index_crypto import IndexCrypto
            self._index_crypto = IndexCrypto(meta_dir)
            if self._index_crypto.is_locked():
                self._index_crypto.unlock()

        self.metadata = MetadataStore(meta_dir)
        self.index = SemanticIndex(meta_dir)
        self.pipeline = CompressionPipeline(meta_dir)

        # Merkle tree — integrity verification across all artifacts
        from .merkle import MerkleTree
        self._merkle_path = meta_dir / "merkle-tree.json"
        if self._merkle_path.exists():
            self.merkle = MerkleTree.load(str(self._merkle_path))
        else:
            self.merkle = MerkleTree()

        # Audit logging — disabled by default, opt-in via config
        self._audit = None
        if config.audit_log:
            from .audit import AuditLogger
            self._audit = AuditLogger(meta_dir)

    def lock_index(self) -> None:
        """Encrypt the index bundle. Call at session end.

        Bundles all index files (semantic index, embeddings, HNSW graphs,
        LSH tables, PQ codebook, registry, audit log, boilerplate cache)
        into a single encrypted .encf file. Plaintext deleted.

        After locking, the index cannot be searched until unlock.
        """
        if self._index_crypto:
            # Save all state before locking
            self.metadata.save(force=True)
            self.index.save(force=True)
            self._index_crypto.lock()

    def __del__(self) -> None:
        """Auto-lock index on garbage collection if encryption is enabled."""
        try:
            self.lock_index()
        except Exception:
            pass  # Don't raise in __del__

    def _log(self, method: str, **kwargs) -> None:
        """Log an event if audit logging is enabled."""
        if self._audit:
            getattr(self._audit, method)(**kwargs)

    # ── Merkle Integrity ──

    def _save_merkle(self) -> None:
        """Persist the Merkle tree to disk."""
        self.merkle.save(str(self._merkle_path))

    @property
    def merkle_root(self) -> Optional[str]:
        """Current Merkle root hash. One hash that covers all artifacts."""
        return self.merkle.root_hex

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify all artifact hashes against the Merkle tree.

        Returns (all_valid, list_of_issues).
        If the Merkle root matches the recomputed tree, all artifacts
        are intact. If not, identifies which artifacts diverged.
        """
        if self.merkle.leaf_count == 0:
            return True, ["No artifacts in Merkle tree yet"]

        # Recompute tree from current artifact hashes
        from .merkle import MerkleTree
        fresh = MerkleTree()
        issues: list[str] = []

        for key, meta in self.metadata._artifacts.items():
            if meta.sha256:
                fresh.add_hex(meta.sha256)
            elif meta.tier == "hot" and Path(meta.path).exists():
                # Recompute hash for hot artifacts
                current = compute_sha256(Path(meta.path))
                fresh.add_hex(current)

        if fresh.root_hex == self.merkle.root_hex:
            return True, []

        issues.append(
            f"Merkle root mismatch: stored={self.merkle.root_hex[:16]}... "
            f"computed={fresh.root_hex[:16] if fresh.root_hex else 'empty'}..."
        )
        return False, issues

    def proof_for_artifact(self, path: Path) -> Optional[dict]:
        """
        Generate a Merkle proof for a specific artifact.

        Proves this artifact is part of the authenticated memory store
        without revealing any other artifacts. Returns proof as dict,
        or None if artifact not in tree.
        """
        from .merkle import MerkleProof
        meta = self.metadata.get(path)
        if not meta or not meta.sha256:
            return None

        # Find the leaf index by matching hash
        target = bytes.fromhex(meta.sha256)
        for i, leaf in enumerate(self.merkle.leaves):
            if leaf == target:
                proof = self.merkle.proof(i)
                return proof.to_dict()

        # Hash not in tree — artifact was added before Merkle was enabled
        return None

    def _encrypt_if_enabled(self, compressed_path: Path,
                            tier: str = "warm") -> tuple[Path, bool]:
        """Encrypt a compressed file if encryption is configured.

        Supports two modes:
          SIMPLE: whole-file encryption with single recipient key.
          ENVELOPE: per-artifact DEK encrypted with tier's public key.
            Stores .envelope.json header alongside the encrypted file.

        Returns (final_path, was_encrypted). Cleans up on failure.
        """
        enc = self.config.encryption
        if not enc.enabled:
            return compressed_path, False

        if enc.envelope_mode:
            return self._encrypt_envelope(compressed_path, tier)
        elif enc.recipient_pubkey:
            return self._encrypt_simple(compressed_path, tier)
        else:
            return compressed_path, False

    def _encrypt_simple(self, compressed_path: Path, tier: str = "warm") -> tuple[Path, bool]:
        """Simple mode: whole-file encryption with single key via sidecar."""
        try:
            from .encryption import encrypt_file
            encrypted_path = encrypt_file(compressed_path, tier)
            compressed_path.unlink()
            return encrypted_path, True
        except (OSError, EncryptionError):
            enc_candidate = compressed_path.with_suffix(
                compressed_path.suffix + ".encf"
            )
            if enc_candidate.exists():
                enc_candidate.unlink()
            raise

    def _encrypt_envelope(self, compressed_path: Path,
                          tier: str) -> tuple[Path, bool]:
        """Envelope mode: per-artifact DEK encrypted with tier's public key.

        Each artifact gets a unique 256-bit DEK. The DEK is encrypted
        asymmetrically with the tier's public key and stored in an
        .envelope.json header. The data is encrypted via the Rust sidecar
        using ML-KEM-768 + X25519 hybrid KEM and AES-256-GCM.
        """
        from .envelope import (
            EnvelopeEncryptor, AsymmetricKeyConfig, TierKeyPair,
            ENVELOPE_HEADER_EXT,
        )

        # Build tier key config from EncryptionConfig fields
        enc = self.config.encryption
        pubkey_map = {
            "warm": enc.warm_pubkey,
            "cold": enc.cold_pubkey,
            "frozen": enc.frozen_pubkey,
        }
        source_map = {
            "warm": enc.warm_private_source,
            "cold": enc.cold_private_source,
            "frozen": enc.frozen_private_source,
        }

        tier_pubkey = pubkey_map.get(tier)
        if not tier_pubkey:
            return compressed_path, False

        # Create envelope (generates DEK, encrypts DEK with tier pubkey)
        key_config = AsymmetricKeyConfig(
            enabled=True,
            warm=TierKeyPair(
                pubkey=pubkey_map.get("warm", "") or "",
                private_key_source=source_map.get("warm", "") or "",
            ),
            cold=TierKeyPair(
                pubkey=pubkey_map.get("cold", "") or "",
                private_key_source=source_map.get("cold", "") or "",
            ),
            key_generation=enc.key_generation,
        )
        encryptor = EnvelopeEncryptor(key_config)
        header, dek = encryptor.create_envelope(compressed_path, tier)

        # Encrypt the data file with the tier's key via sidecar
        from .encryption import encrypt_file
        try:
            encrypted_path = encrypt_file(compressed_path, tier)
            compressed_path.unlink()

            # Store envelope header alongside encrypted file
            header_path = encrypted_path.with_suffix(
                encrypted_path.suffix + ENVELOPE_HEADER_EXT
            )
            from .fileutil import atomic_write_text
            atomic_write_text(header_path, header.to_json())

            return encrypted_path, True
        except (OSError, EncryptionError):
            enc_candidate = compressed_path.with_suffix(
                compressed_path.suffix + ".encf"
            )
            if enc_candidate.exists():
                enc_candidate.unlink()
            raise

    def _decrypt_envelope(self, encrypted_path: Path, tier: str,
                          original_path: Path) -> Path:
        """Decrypt an envelope-encrypted artifact using the tier's private key.

        The sidecar retrieves the private key from the OS credential vault,
        decrypts in-process using ML-KEM-768 + AES-256-GCM, and zeroes
        the key. Python never sees any private key material.
        """
        from .encryption import decrypt_file
        output = encrypted_path.with_suffix("")
        decrypt_file(encrypted_path, tier, output_path=output)
        return output

    def scan(self) -> list[Path]:
        """
        Discover all artifacts across configured scan targets.

        Delegates to scanner.iter_artifacts() for the actual filesystem
        walk. Single implementation of scan logic (SME F3.5 fix).
        """
        from .scanner import iter_artifacts
        return list(iter_artifacts(self.config.scan_targets))

    def register_all(self, paths: list[Path]) -> None:
        """Register all discovered files in the metadata store and semantic index.

        Transparently handles gzip-compressed files (.gz) by decompressing
        in memory for indexing. The file on disk stays compressed.
        """
        import gzip

        for p in paths:
            meta = self.metadata.register(p)
            # Index content for context enhancement (only if not already indexed)
            if not self.index.get(p) and p.exists():
                try:
                    if p.name.endswith(".gz"):
                        # Decompress gzip in memory for indexing only
                        with gzip.open(p, "rt", errors="replace") as f:
                            content = f.read(102_400)  # Cap at 100KB for indexing
                    else:
                        content = p.read_text(errors="replace")
                    self.index.index_artifact(p, content, meta)
                except (PermissionError, OSError, gzip.BadGzipFile):
                    pass  # Skip unreadable or corrupt files
        self.metadata.save()
        self.index.save()

        # Add to Merkle tree — each artifact gets a leaf
        for p in paths:
            meta = self.metadata.get(p)
            if meta and meta.sha256:
                self.merkle.add_hex(meta.sha256)
        self._save_merkle()

        # Encrypt hot artifacts at rest if configured
        if (self.config.encryption.enabled
                and self.config.encryption.encrypt_hot
                and self.config.encryption.recipient_pubkey):
            self._encrypt_hot_artifacts(paths)

    def _encrypt_hot_artifacts(self, paths: list[Path]) -> None:
        """Encrypt hot-tier artifacts in place (opt-in, off by default).

        Only encrypts files that aren't already encrypted (.encf).
        The encrypted file replaces the original. Recall requires
        decryption (Touch ID / vault access).
        """
        from .encryption import encrypt_file
        for p in paths:
            if not p.exists() or p.name.endswith(".encf"):
                continue
            meta = self.metadata.get(p)
            if not meta:
                continue
            try:
                encrypted = encrypt_file(p, "hot", remove_original=True)
                meta.encrypted = True
                meta.compressed_path = str(encrypted)
                self.metadata._dirty = True
            except (OSError, EncryptionError):
                self._log("error", operation="hot-encrypt",
                          short_hash=meta.sha256[:6] if meta.sha256 else "")
        self.metadata.save()

    def evaluate_and_tier(self) -> list[TierAction]:
        """
        Evaluate all tracked artifacts and perform tier transitions.

        Returns list of actions taken (or would-be-taken in dry_run mode).
        """
        policy = self.config.tier_policy
        actions: list[TierAction] = []

        # Phase 1: HOT -> WARM
        warm_candidates = self.metadata.candidates_for_warm(
            age_hours=policy.hot_to_warm_age_hours,
            idle_hours=policy.hot_to_warm_idle_hours,
            min_size=policy.min_file_size_bytes,
        )

        for meta in warm_candidates:
            action = self._tier_to_warm(meta)
            if action:
                actions.append(action)

        # Phase 2: WARM -> COLD
        cold_candidates = self.metadata.candidates_for_cold(
            age_hours=policy.warm_to_cold_age_hours,
            idle_hours=policy.warm_to_cold_idle_hours,
        )

        for meta in cold_candidates:
            action = self._tier_to_cold(meta)
            if action:
                actions.append(action)

        # Phase 3: COLD -> FROZEN (recompress at highest level)
        frozen_candidates = self.metadata.candidates_for_frozen(
            age_hours=policy.cold_to_frozen_age_hours,
            idle_hours=policy.cold_to_frozen_idle_hours,
        )

        for meta in frozen_candidates:
            action = self._tier_to_frozen(meta)
            if action:
                actions.append(action)

        self.metadata.save()
        self.index.save()
        return actions

    def _tier_to_warm(self, meta: ArtifactMeta) -> Optional[TierAction]:
        """Compress a hot artifact to warm tier via multi-stage pipeline.

        Pipeline: minify JSON → zstd-3 (~4-5x ratio).
        """
        src = Path(meta.path)
        if not src.exists():
            return None

        # Verify file integrity before compression
        if meta.sha256:
            current_hash = compute_sha256(src)
            if current_hash != meta.sha256:
                raise IntegrityError(
                    f"File modified since registration: {src} "
                    f"(expected {meta.sha256[:16]}..., got {current_hash[:16]}...)"
                )

        action = TierAction(
            path=meta.path,
            from_tier=Tier.HOT.value,
            to_tier=Tier.WARM.value,
            original_size=meta.original_size,
            dry_run=self.config.dry_run,
        )

        if self.config.dry_run:
            return action

        # Multi-stage pipeline: minify → zstd-3
        output_path = src.with_suffix(src.suffix + ".zst")
        result = self.pipeline.compress_warm(src, output_path)

        # Remove original if configured
        if not self.config.tier_policy.keep_originals and src.exists():
            src.unlink()

        compressed_path = result.output_path
        compressed_path, encrypted = self._encrypt_if_enabled(compressed_path, tier="warm")

        action.new_size = compressed_path.stat().st_size
        action.ratio = result.ratio
        action.encrypted = encrypted

        # Update metadata — clear sha256 since pipeline applies lossy
        # transformations (minification, boilerplate stripping) that change
        # the content. Integrity is maintained by the pipeline, not raw hash.
        # Clear sha256 — pipeline transforms content (minification is lossy
        # for whitespace), so the original hash no longer matches decompressed
        meta_entry = self.metadata.get(src)
        if meta_entry:
            meta_entry.sha256 = ""

        self.metadata.update_tier(
            src, Tier.WARM,
            compressed_path=str(compressed_path),
            compressed_size=action.new_size,
            ratio=result.ratio,
            encrypted=encrypted,
        )
        self.index.update_tier(src, Tier.WARM.value)
        self._log("tier", from_tier="hot", to_tier="warm",
                  artifact_hash=meta.sha256 or "", ratio=result.ratio)

        return action

    def _tier_to_cold(self, meta: ArtifactMeta) -> Optional[TierAction]:
        """Recompress a warm artifact via cold pipeline.

        Pipeline: decompress warm → strip boilerplate → minify →
        dictionary-trained zstd-9 (~8-12x ratio).
        """
        compressed = Path(meta.compressed_path) if meta.compressed_path else None
        if not compressed or not compressed.exists():
            return None

        action = TierAction(
            path=meta.path,
            from_tier=Tier.WARM.value,
            to_tier=Tier.COLD.value,
            original_size=meta.original_size,
            dry_run=self.config.dry_run,
        )

        if self.config.dry_run:
            return action

        # Decompress warm tier back to raw content for re-processing
        working_path = compressed
        if meta.encrypted and self.config.encryption.enabled:
            from .encryption import decrypt_file
            working_path = decrypt_file(compressed, "warm")

        try:
            raw_path = decompress_file(working_path, remove_compressed=True)
        except (OSError, zstd.ZstdError):
            # Clean up decrypted intermediate on failure
            if working_path != compressed and working_path.exists():
                working_path.unlink()
            raise

        # Run cold pipeline on raw content
        cold_output = raw_path.with_suffix(raw_path.suffix + ".cold.zst")
        try:
            result = self.pipeline.compress_cold(raw_path, cold_output)
        except (OSError, zstd.ZstdError):
            if raw_path.exists():
                raw_path.unlink()
            raise

        # Clean up raw intermediate
        if raw_path.exists():
            raw_path.unlink()

        final_path = result.output_path
        final_path, encrypted = self._encrypt_if_enabled(final_path, tier="cold")

        action.new_size = final_path.stat().st_size
        action.ratio = result.ratio
        action.encrypted = encrypted

        self.metadata.update_tier(
            Path(meta.path), Tier.COLD,
            compressed_path=str(final_path),
            compressed_size=action.new_size,
            ratio=result.ratio,
            encrypted=encrypted,
        )
        self.index.update_tier(Path(meta.path), Tier.COLD.value)
        self._log("tier", from_tier="warm", to_tier="cold",
                  artifact_hash=meta.sha256 or "", ratio=result.ratio)

        return action

    def _tier_to_frozen(self, meta: ArtifactMeta) -> Optional[TierAction]:
        """Recompress a cold artifact via frozen pipeline.

        Pipeline: decompress cold → restore boilerplate → strip →
        minify → columnar Parquet + dict + zstd-19 (~20-50x ratio).
        Falls back to dict-zstd-19 for non-JSONL content.
        """
        compressed = Path(meta.compressed_path) if meta.compressed_path else None
        if not compressed or not compressed.exists():
            return None

        action = TierAction(
            path=meta.path,
            from_tier=Tier.COLD.value,
            to_tier=Tier.FROZEN.value,
            original_size=meta.original_size,
            dry_run=self.config.dry_run,
        )

        if self.config.dry_run:
            return action

        # Decompress cold tier back to raw content
        working_path = compressed
        if meta.encrypted and self.config.encryption.enabled:
            from .encryption import decrypt_file
            try:
                working_path = decrypt_file(compressed, "cold")
            except (OSError, EncryptionError) as e:
                raise DecryptionRequiredError(
                    f"Failed to decrypt cold-tier artifact for frozen transition: {type(e).__name__}",
                    tier=Tier.COLD.value, path=meta.path,
                ) from e

        # Decompress cold zstd, restore boilerplate for re-processing
        raw_bytes = self.pipeline.decompress_cold(working_path)
        if working_path.exists():
            working_path.unlink()

        # Write raw content to temp for frozen pipeline input
        import tempfile
        raw_fd, raw_str = tempfile.mkstemp(suffix=".jsonl", prefix="engram-")
        os.chmod(raw_str, 0o600)  # SECURITY: restrict before writing plaintext
        raw_path = Path(raw_str)
        with open(raw_fd, "wb") as f:
            f.write(raw_bytes)

        # Run frozen pipeline (Parquet or dict-zstd-19)
        frozen_output = raw_path.with_suffix(".frozen")
        try:
            result = self.pipeline.compress_frozen(raw_path, frozen_output)
        except Exception:
            # Broad catch: compress_frozen can raise ImportError (pyarrow),
            # ValueError, or any pipeline error. Clean up plaintext.
            if raw_path.exists():
                raw_path.unlink()
            raise

        if raw_path.exists():
            raw_path.unlink()

        final_path = result.output_path
        final_path, encrypted = self._encrypt_if_enabled(final_path, tier="frozen")

        action.new_size = final_path.stat().st_size
        action.ratio = result.ratio
        action.encrypted = encrypted

        self.metadata.update_tier(
            Path(meta.path), Tier.FROZEN,
            compressed_path=str(final_path),
            compressed_size=action.new_size,
            ratio=result.ratio,
            encrypted=encrypted,
        )
        self.index.update_tier(Path(meta.path), Tier.FROZEN.value)
        self._log("tier", from_tier="cold", to_tier="frozen",
                  artifact_hash=meta.sha256 or "", ratio=result.ratio)

        return action

    def recall(self, original_path: Path) -> Optional[Path]:
        """
        Recall (decompress + decrypt) an artifact back to hot tier.

        This is the "thaw" operation — like Elasticsearch unfreezing a
        searchable snapshot or Splunk SmartStore cache-on-read.

        Args:
            original_path: The original file path (pre-compression).

        Returns:
            Path to decompressed file, or None if not found.

        Raises:
            PathContainmentError: If registry paths escape allowed directories.
            IntegrityError: If decompressed content doesn't match stored hash.
        """
        # Validate recall target is within scan targets
        if not _is_within_scan_targets(original_path, self.config):
            raise PathContainmentError(
                f"Recall target not within any scan target: {original_path}"
            )

        meta = self.metadata.get(original_path)
        if not meta:
            raise ArtifactNotFoundError(
                f"No record of this artifact in the registry: {original_path}",
                tier="unknown", path=str(original_path),
            )

        if meta.tier == Tier.HOT.value:
            if original_path.exists():
                return original_path
            raise ArtifactNotFoundError(
                f"Hot artifact file missing from disk: {original_path}",
                tier="hot", path=str(original_path),
            )

        # Validate compressed_path from registry
        if not meta.compressed_path:
            raise ArtifactNotFoundError(
                f"Artifact is in {meta.tier} tier but has no compressed path: {original_path}",
                tier=meta.tier, path=str(original_path),
            )
        compressed = _validate_registry_path(
            meta.compressed_path, self.config, "compressed_path"
        )
        if not compressed.exists():
            raise ArtifactNotFoundError(
                f"Compressed file missing from disk: {meta.compressed_path} "
                f"(artifact was in {meta.tier} tier)",
                tier=meta.tier, path=str(original_path),
            )

        working_path = compressed

        # Decrypt if needed
        if meta.encrypted:
            if not self.config.encryption.enabled:
                raise DecryptionRequiredError(
                    f"Artifact in {meta.tier} tier is encrypted but encryption is not "
                    f"configured. Enable encryption in config and provide the {meta.tier} "
                    f"tier private key to recall this artifact.",
                    tier=meta.tier, path=str(original_path),
                )

            enc = self.config.encryption
            try:
                if enc.envelope_mode:
                    # Envelope mode: use tier-specific private key source
                    working_path = self._decrypt_envelope(
                        compressed, meta.tier, original_path
                    )
                else:
                    # Simple mode: use tier key via sidecar
                    from .encryption import decrypt_file
                    working_path = decrypt_file(compressed, meta.tier)
            except (OSError, EncryptionError) as e:
                raise DecryptionRequiredError(
                    f"Failed to decrypt {meta.tier}-tier artifact: {original_path}. "
                    f"Check that the correct private key is accessible. "
                    f"For Keychain: ensure Touch ID is available. "
                    f"For Vault/KMS: ensure credentials are valid. Error: {type(e).__name__}",
                    tier=meta.tier, path=str(original_path),
                ) from e

        # Decompress — always clean up decrypted intermediate on failure
        try:
            output = decompress_file(working_path, output_path=original_path)
        except (OSError, zstd.ZstdError) as e:
            # Clean up decrypted intermediate to avoid plaintext leak (CWE-459)
            if working_path != compressed and working_path.exists():
                working_path.unlink()
            raise DecompressionError(
                f"Failed to decompress {meta.tier}-tier artifact: {original_path}. "
                f"The compressed file may be corrupted. Error: {type(e).__name__}",
                tier=meta.tier, path=str(original_path),
            ) from e

        # Verify integrity after decompression
        if meta.sha256:
            restored_hash = compute_sha256(output)
            if restored_hash != meta.sha256:
                # Remove the unverified output AND decrypted intermediate
                output.unlink()
                if working_path != compressed and working_path.exists():
                    working_path.unlink()
                raise IntegrityError(
                    f"Integrity check failed on recall: {original_path} "
                    f"(expected {meta.sha256[:16]}..., got {restored_hash[:16]}...)"
                )

        # Clean up intermediate decrypt file if different from compressed
        if working_path != compressed and working_path.exists():
            working_path.unlink()

        # Update metadata back to hot
        self.metadata.update_tier(
            original_path, Tier.HOT,
            compressed_path=meta.compressed_path,  # keep reference
            compressed_size=meta.compressed_size,
            ratio=meta.compression_ratio,
            encrypted=False,
        )
        self.metadata.touch(original_path)
        self.index.update_tier(original_path, Tier.HOT.value)
        self._log("recall", tier=meta.tier, artifact_hash=meta.sha256 or "")
        self.metadata.save()
        self.index.save()

        return output

    def run(self) -> list[TierAction]:
        """
        Full lifecycle: scan -> register -> evaluate -> tier.

        Returns list of all actions taken.
        """
        discovered = self.scan()
        self.register_all(discovered)
        return self.evaluate_and_tier()

    def get_context(self, query: str = "",
                     budget_chars: int = DEFAULT_CONTEXT_BUDGET_CHARS) -> str:
        """
        Get context-enhanced memory for AI assistant injection.

        This is the primary interface for context window enhancement.
        Returns a formatted block of relevant memories that the AI
        assistant can include in its prompt.

        Args:
            query: Optional task/query to bias relevance scoring.
            budget_chars: Maximum characters for the context block.

        Returns:
            Formatted context string ready for prompt injection.
        """
        budget = ContextBudget(total_chars=budget_chars)
        builder = ContextBuilder(self.index, self.metadata, budget)
        return builder.build_session_context(query)

    def search_memory(self, query: str, max_results: int = 10) -> list:
        """
        Search indexed memories by relevance.

        Returns list of ArtifactSummary objects matching the query.
        """
        return self.index.search(query, max_results)

    def status(self) -> dict:
        """Return current tier distribution, compression stats, and index stats."""
        stats = self.metadata.stats()
        entries = self.index.all_entries()
        stats["indexed_artifacts"] = len(entries)
        stats["total_keywords"] = sum(len(e.keywords) for e in entries)
        return stats

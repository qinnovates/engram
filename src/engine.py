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

import subprocess
from pathlib import Path

import zstandard as zstd
from typing import Optional

from .config import EngineConfig
from .metadata import MetadataStore, Tier, ArtifactMeta, compute_sha256
from .compressor import compress_file, decompress_file, recompress_file
from .encryption import encrypt_file, decrypt_file, EncryptionError
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
        self.metadata = MetadataStore(meta_dir)
        self.index = SemanticIndex(meta_dir)

        # Audit logging — disabled by default, opt-in via config
        self._audit = None
        if config.audit_log:
            from .audit import AuditLogger
            self._audit = AuditLogger(meta_dir)

    def _log(self, method: str, **kwargs) -> None:
        """Log an event if audit logging is enabled."""
        if self._audit:
            getattr(self._audit, method)(**kwargs)

    def _encrypt_if_enabled(self, compressed_path: Path) -> tuple[Path, bool]:
        """Encrypt a compressed file if encryption is configured.

        Returns (final_path, was_encrypted). Cleans up on failure.
        Shared by _tier_to_warm, _tier_to_cold, _tier_to_frozen.
        """
        if not (self.config.encryption.enabled
                and self.config.encryption.recipient_pubkey):
            return compressed_path, False

        try:
            encrypted_path = encrypt_file(compressed_path, self.config.encryption)
            compressed_path.unlink()
            return encrypted_path, True
        except (OSError, subprocess.SubprocessError, EncryptionError):
            enc_candidate = compressed_path.with_suffix(
                compressed_path.suffix + ".age"
            )
            if enc_candidate.exists():
                enc_candidate.unlink()
            raise

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
        """Compress a hot artifact to warm tier (zstd level 3)."""
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

        # Compress
        result = compress_file(
            src,
            level=self.config.tier_policy.warm_compression_level,
            remove_original=not self.config.tier_policy.keep_originals,
        )

        compressed_path = result.output_path
        compressed_path, encrypted = self._encrypt_if_enabled(compressed_path)

        action.new_size = compressed_path.stat().st_size
        action.ratio = result.ratio
        action.encrypted = encrypted

        # Update metadata and semantic index
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
        """Recompress a warm artifact to cold tier (zstd level 9)."""
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

        # If encrypted, decrypt first
        working_path = compressed
        was_encrypted = meta.encrypted

        if was_encrypted and self.config.encryption.enabled:
            working_path = decrypt_file(compressed, self.config.encryption)
            compressed.unlink()

        # Recompress at cold level — with cleanup on failure
        try:
            result = recompress_file(
                working_path,
                new_level=self.config.tier_policy.cold_compression_level,
            )
        except (OSError, zstd.ZstdError):
            # Clean up decrypted intermediate if it exists
            if working_path != compressed and working_path.exists():
                working_path.unlink()
            raise

        final_path = result.output_path
        final_path, encrypted = self._encrypt_if_enabled(final_path)

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
        """Recompress a cold artifact to frozen tier (highest compression)."""
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

        # Same flow as cold but with frozen compression level
        working_path = compressed
        was_encrypted = meta.encrypted

        if was_encrypted and self.config.encryption.enabled:
            try:
                working_path = decrypt_file(compressed, self.config.encryption)
                compressed.unlink()
            except (OSError, subprocess.SubprocessError, EncryptionError) as e:
                raise DecryptionRequiredError(
                    f"Failed to decrypt cold-tier artifact for frozen transition: {e}",
                    tier=Tier.COLD.value, path=meta.path,
                ) from e

        try:
            result = recompress_file(
                working_path,
                new_level=self.config.tier_policy.frozen_compression_level,
            )
        except (OSError, zstd.ZstdError):
            if working_path != compressed and working_path.exists():
                working_path.unlink()
            raise

        final_path = result.output_path
        final_path, encrypted = self._encrypt_if_enabled(final_path)

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
            try:
                working_path = decrypt_file(compressed, self.config.encryption)
            except Exception as e:
                raise DecryptionRequiredError(
                    f"Failed to decrypt {meta.tier}-tier artifact: {original_path}. "
                    f"Check that the correct private key is accessible. "
                    f"For Keychain: ensure Touch ID is available. "
                    f"For Vault/KMS: ensure credentials are valid. Error: {e}",
                    tier=meta.tier, path=str(original_path),
                ) from e

        # Decompress
        try:
            output = decompress_file(working_path, output_path=original_path)
        except Exception as e:
            raise DecompressionError(
                f"Failed to decompress {meta.tier}-tier artifact: {original_path}. "
                f"The compressed file may be corrupted. Error: {e}",
                tier=meta.tier, path=str(original_path),
            ) from e

        # Verify integrity after decompression
        if meta.sha256:
            restored_hash = compute_sha256(output)
            if restored_hash != meta.sha256:
                # Remove the unverified output
                output.unlink()
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

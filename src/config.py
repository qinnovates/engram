"""
Configuration schema and defaults for tiered-memory-engine.

Tier model (inspired by Splunk SmartStore + Elasticsearch ILM):
  HOT  -> no compression, immediate access
  WARM -> zstd level 3 (~3.2x ratio, ~234 MB/s compress)
  COLD -> zstd level 9 (~3.5x ratio, ~40 MB/s compress, slowest recall)

Transition triggers are age-based (primary) + access-recency (secondary),
matching production patterns from Splunk LRU and S3 Intelligent-Tiering.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# --- Default thresholds (in hours) ---
DEFAULT_HOT_TO_WARM_AGE_HOURS = 48       # 2 days without access -> warm
DEFAULT_WARM_TO_COLD_AGE_HOURS = 336     # 14 days without access -> cold
DEFAULT_COLD_TO_FROZEN_AGE_HOURS = 2160  # 90 days without access -> frozen
DEFAULT_HOT_TO_WARM_IDLE_HOURS = 24      # no access in 24h -> eligible for warm
DEFAULT_WARM_TO_COLD_IDLE_HOURS = 168    # no access in 7d -> eligible for cold
DEFAULT_COLD_TO_FROZEN_IDLE_HOURS = 720  # 30d idle -> eligible for frozen

# --- Compression levels (zstd) ---
WARM_COMPRESSION_LEVEL = 3   # balanced: ~3.2x ratio, fast
COLD_COMPRESSION_LEVEL = 9   # high ratio: ~3.5x, slow compress
FROZEN_COMPRESSION_LEVEL = 19 # maximum: ~3.8x, very slow compress, archival

# --- Valid zstd compression level range ---
ZSTD_MIN_LEVEL = 1
ZSTD_MAX_LEVEL = 22

# --- File extension for compressed artifacts ---
COMPRESSED_EXT = ".zst"
TIER_METADATA_FILE = ".tier-metadata.json"

# --- Sensitive directories that must never be scan targets ---
BLOCKED_SCAN_PATHS = {
    ".ssh", ".gnupg", ".gpg", ".aws", ".azure", ".config/gcloud",
    ".docker", ".kube", ".vault-token", ".terraform",
}


class ConfigValidationError(ValueError):
    """Raised when config contains invalid or dangerous values."""
    pass


def _is_path_within_allowed_roots(p: Path) -> bool:
    """Check if a resolved path is within allowed root directories.

    Allows: user's home directory and system temp directories (for testing).
    """
    import tempfile
    resolved = p.resolve()
    allowed_roots = [Path.home(), Path(tempfile.gettempdir()).resolve()]
    for root in allowed_roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _is_sensitive_path(p: Path) -> bool:
    """Check if a path resolves to a known sensitive directory."""
    resolved = p.resolve()
    home = Path.home()
    try:
        rel = resolved.relative_to(home)
        # Check if any component matches blocked paths
        rel_str = str(rel)
        for blocked in BLOCKED_SCAN_PATHS:
            if rel_str == blocked or rel_str.startswith(blocked + "/"):
                return True
    except ValueError:
        pass
    return False


@dataclass
class ScanTarget:
    """A directory or glob pattern to scan for tierable artifacts."""
    path: str
    pattern: str = "*"           # glob pattern within path
    recursive: bool = True
    description: str = ""

    def resolve(self) -> Path:
        return Path(os.path.expanduser(self.path))

    def validate(self) -> None:
        """Validate scan target path is safe."""
        resolved = self.resolve().resolve()
        # Must be within user's home directory
        if not _is_path_within_allowed_roots(resolved):
            raise ConfigValidationError(
                f"Scan target must be within home directory: {self.path} "
                f"resolves to {resolved}"
            )
        # Must not target sensitive directories
        if _is_sensitive_path(resolved):
            raise ConfigValidationError(
                f"Scan target points to sensitive directory: {self.path} "
                f"resolves to {resolved}"
            )


@dataclass
class EncryptionConfig:
    """Optional PQKC encryption via age (ML-KEM-768 hybrid)."""
    enabled: bool = False
    # Path to age recipient public key (age1... or SSH pubkey)
    recipient_pubkey: Optional[str] = None
    # Path to age identity (private key) for decryption
    identity_path: Optional[str] = None
    # If True, encrypts AFTER compression (compress-then-encrypt)
    encrypt_after_compress: bool = True


@dataclass
class TierPolicy:
    """Defines when and how artifacts move between tiers."""
    hot_to_warm_age_hours: int = DEFAULT_HOT_TO_WARM_AGE_HOURS
    warm_to_cold_age_hours: int = DEFAULT_WARM_TO_COLD_AGE_HOURS
    cold_to_frozen_age_hours: int = DEFAULT_COLD_TO_FROZEN_AGE_HOURS
    hot_to_warm_idle_hours: int = DEFAULT_HOT_TO_WARM_IDLE_HOURS
    warm_to_cold_idle_hours: int = DEFAULT_WARM_TO_COLD_IDLE_HOURS
    cold_to_frozen_idle_hours: int = DEFAULT_COLD_TO_FROZEN_IDLE_HOURS
    warm_compression_level: int = WARM_COMPRESSION_LEVEL
    cold_compression_level: int = COLD_COMPRESSION_LEVEL
    frozen_compression_level: int = FROZEN_COMPRESSION_LEVEL
    # Minimum file size (bytes) to bother compressing
    min_file_size_bytes: int = 512
    # Keep original after compression (for safety during first run)
    keep_originals: bool = False

    def __post_init__(self) -> None:
        """Validate all fields are within safe ranges."""
        if self.hot_to_warm_age_hours < 0:
            raise ConfigValidationError(
                f"hot_to_warm_age_hours must be >= 0, got {self.hot_to_warm_age_hours}")
        if self.warm_to_cold_age_hours < 0:
            raise ConfigValidationError(
                f"warm_to_cold_age_hours must be >= 0, got {self.warm_to_cold_age_hours}")
        if self.hot_to_warm_idle_hours < 0:
            raise ConfigValidationError(
                f"hot_to_warm_idle_hours must be >= 0, got {self.hot_to_warm_idle_hours}")
        if self.warm_to_cold_idle_hours < 0:
            raise ConfigValidationError(
                f"warm_to_cold_idle_hours must be >= 0, got {self.warm_to_cold_idle_hours}")
        if not (ZSTD_MIN_LEVEL <= self.warm_compression_level <= ZSTD_MAX_LEVEL):
            raise ConfigValidationError(
                f"warm_compression_level must be {ZSTD_MIN_LEVEL}-{ZSTD_MAX_LEVEL}, "
                f"got {self.warm_compression_level}")
        if not (ZSTD_MIN_LEVEL <= self.cold_compression_level <= ZSTD_MAX_LEVEL):
            raise ConfigValidationError(
                f"cold_compression_level must be {ZSTD_MIN_LEVEL}-{ZSTD_MAX_LEVEL}, "
                f"got {self.cold_compression_level}")
        if not (ZSTD_MIN_LEVEL <= self.frozen_compression_level <= ZSTD_MAX_LEVEL):
            raise ConfigValidationError(
                f"frozen_compression_level must be {ZSTD_MIN_LEVEL}-{ZSTD_MAX_LEVEL}, "
                f"got {self.frozen_compression_level}")
        if self.cold_to_frozen_age_hours < 0:
            raise ConfigValidationError(
                f"cold_to_frozen_age_hours must be >= 0, got {self.cold_to_frozen_age_hours}")
        if self.cold_to_frozen_idle_hours < 0:
            raise ConfigValidationError(
                f"cold_to_frozen_idle_hours must be >= 0, got {self.cold_to_frozen_idle_hours}")
        if self.min_file_size_bytes < 0:
            raise ConfigValidationError(
                f"min_file_size_bytes must be >= 0, got {self.min_file_size_bytes}")


@dataclass
class EngineConfig:
    """Top-level configuration for the tiered memory engine."""
    scan_targets: list[ScanTarget] = field(default_factory=list)
    tier_policy: TierPolicy = field(default_factory=TierPolicy)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    # Where to store tier metadata (access times, tier state)
    metadata_dir: str = "~/.tiered-memory"
    # Dry run mode — report what would happen without changing files
    dry_run: bool = False
    # Verbose output
    verbose: bool = False

    def _validate_metadata_dir(self) -> Path:
        """Validate and resolve metadata_dir — must be within home."""
        p = Path(os.path.expanduser(self.metadata_dir)).resolve()
        if not _is_path_within_allowed_roots(p):
            raise ConfigValidationError(
                f"metadata_dir must be within home directory: {self.metadata_dir} "
                f"resolves to {p}"
            )
        return p

    def resolve_metadata_dir(self) -> Path:
        p = self._validate_metadata_dir()
        p.mkdir(parents=True, exist_ok=True)
        # Enforce directory permissions
        p.chmod(0o700)
        return p

    @classmethod
    def default_claude_targets(cls) -> list[ScanTarget]:
        """Default scan targets for Claude Code artifacts."""
        home = str(Path.home())
        return [
            ScanTarget(
                path=f"{home}/.claude/subagents",
                pattern="*.jsonl",
                description="Claude subagent conversation logs"
            ),
            ScanTarget(
                path=f"{home}/.claude/projects",
                pattern="**/memory/**/*",
                description="Claude project memory files"
            ),
            ScanTarget(
                path=f"{home}/.claude/todos",
                pattern="*.json",
                description="Claude task/todo artifacts"
            ),
        ]

    @classmethod
    def default_generic_targets(cls) -> list[ScanTarget]:
        """Default targets for generic AI assistant artifacts."""
        home = str(Path.home())
        return [
            ScanTarget(
                path=f"{home}/.local/share/ai-memory",
                pattern="*",
                description="Generic AI memory store"
            ),
        ]

    def validate(self) -> None:
        """Run all config validations. Called after loading."""
        self._validate_metadata_dir()
        for target in self.scan_targets:
            target.validate()
        # TierPolicy validates in __post_init__

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, raw: str | dict) -> "EngineConfig":
        if isinstance(raw, str):
            data: dict = json.loads(raw)
        else:
            data = raw

        # Extract only known fields to prevent unexpected kwarg injection
        target_dicts = data.get("scan_targets", [])
        targets = []
        known_target_fields = {"path", "pattern", "recursive", "description"}
        for t in target_dicts:
            filtered = {k: v for k, v in t.items() if k in known_target_fields}
            targets.append(ScanTarget(**filtered))

        known_policy_fields = {
            "hot_to_warm_age_hours", "warm_to_cold_age_hours",
            "cold_to_frozen_age_hours",
            "hot_to_warm_idle_hours", "warm_to_cold_idle_hours",
            "cold_to_frozen_idle_hours",
            "warm_compression_level", "cold_compression_level",
            "frozen_compression_level",
            "min_file_size_bytes", "keep_originals",
        }
        policy_data = {k: v for k, v in data.get("tier_policy", {}).items()
                       if k in known_policy_fields}
        policy = TierPolicy(**policy_data)  # __post_init__ validates ranges

        known_enc_fields = {
            "enabled", "recipient_pubkey", "identity_path", "encrypt_after_compress",
        }
        enc_data = {k: v for k, v in data.get("encryption", {}).items()
                    if k in known_enc_fields}
        encryption = EncryptionConfig(**enc_data)

        cfg = cls(
            scan_targets=targets,
            tier_policy=policy,
            encryption=encryption,
            metadata_dir=data.get("metadata_dir", "~/.tiered-memory"),
            dry_run=data.get("dry_run", False),
            verbose=data.get("verbose", False),
        )
        cfg.validate()
        return cfg

    @classmethod
    def load(cls, config_path: str | Path) -> "EngineConfig":
        p = Path(os.path.expanduser(config_path))
        if p.exists():
            return cls.from_json(p.read_text())
        # Return defaults with Claude targets
        cfg = cls()
        cfg.scan_targets = cls.default_claude_targets()
        return cfg

    def save(self, config_path: str | Path) -> None:
        p = Path(os.path.expanduser(config_path))
        p.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write with restricted permissions (config may contain key paths)
        tmp = p.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.to_json())
        tmp.rename(p)

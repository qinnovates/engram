"""
Metadata tracker for artifact access patterns and tier state.

Tracks per-file:
  - creation time
  - last access time (updated on read/decompress)
  - last modified time
  - current tier (hot/warm/cold)
  - file hash (for integrity verification)
  - compression stats (original size, compressed size, ratio)

Stored as a single JSON file per metadata directory, similar to how
Splunk's cache manager tracks bucket access with LRU timestamps.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class Tier(str, Enum):
    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    FROZEN = "frozen"


@dataclass
class ArtifactMeta:
    """Metadata for a single tracked artifact."""
    path: str
    tier: str = Tier.HOT.value
    created_at: float = 0.0
    last_accessed: float = 0.0
    last_modified: float = 0.0
    original_size: int = 0
    compressed_size: int = 0
    compression_ratio: float = 1.0
    sha256: str = ""
    encrypted: bool = False
    compressed_path: Optional[str] = None

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def idle_hours(self) -> float:
        return (time.time() - self.last_accessed) / 3600


class MetadataStore:
    """Persistent metadata store for all tracked artifacts."""

    def __init__(self, metadata_dir: Path):
        self.metadata_dir = metadata_dir
        self.db_path = metadata_dir / "artifact-registry.json"
        self._artifacts: dict[str, ArtifactMeta] = {}
        self._dirty: bool = False
        self._load()

    # Known fields in ArtifactMeta — used to filter out unknown keys
    _KNOWN_FIELDS = {
        "path", "tier", "created_at", "last_accessed", "last_modified",
        "original_size", "compressed_size", "compression_ratio",
        "sha256", "encrypted", "compressed_path",
    }

    def _load(self) -> None:
        if self.db_path.exists():
            try:
                with open(self.db_path) as f:
                    data = json.load(f)
                for key, val in data.get("artifacts", {}).items():
                    filtered = {k: v for k, v in val.items()
                                if k in self._KNOWN_FIELDS}
                    self._artifacts[key] = ArtifactMeta(**filtered)
            except json.JSONDecodeError:
                # Registry is corrupt — save a backup before resetting
                import shutil
                backup = self.db_path.with_suffix(".corrupt.bak")
                shutil.copy2(self.db_path, backup)
                self._artifacts = {}

    def save(self, force: bool = False) -> None:
        if not force and not self._dirty:
            return
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": time.time(),
            "artifact_count": len(self._artifacts),
            "artifacts": {k: asdict(v) for k, v in self._artifacts.items()},
        }
        from .fileutil import atomic_write_text
        atomic_write_text(self.db_path, json.dumps(payload, indent=2))
        self._dirty = False

    def register(self, path: Path) -> ArtifactMeta:
        """Register or update a file in the metadata store."""
        key = str(path.resolve())
        now = time.time()

        if key in self._artifacts:
            meta = self._artifacts[key]
            # DON'T update last_accessed on re-registration — only on explicit
            # recall or touch. Otherwise every scan resets idle timers and
            # nothing ever moves to warm/cold/frozen.
            if path.exists():
                stat = path.stat()
                meta.last_modified = stat.st_mtime
                meta.original_size = stat.st_size
            return meta

        # New artifact — use real file timestamps for correct tier placement
        if path.exists():
            stat = path.stat()
            meta = ArtifactMeta(
                path=key,
                tier=Tier.HOT.value,
                created_at=stat.st_ctime,
                last_accessed=stat.st_atime,  # Real OS access time, not now
                last_modified=stat.st_mtime,
                original_size=stat.st_size,
                sha256=compute_sha256(path),
            )
        else:
            meta = ArtifactMeta(
                path=key,
                created_at=now,
                last_accessed=now,
                last_modified=now,
            )

        self._artifacts[key] = meta
        self._dirty = True
        return meta

    def get(self, path: Path) -> Optional[ArtifactMeta]:
        return self._artifacts.get(str(path.resolve()))

    def touch(self, path: Path) -> None:
        """Update last_accessed timestamp (called on decompress/read)."""
        key = str(path.resolve())
        if key in self._artifacts:
            self._artifacts[key].last_accessed = time.time()
            self._dirty = True

    def update_tier(self, path: Path, tier: Tier, compressed_path: Optional[str] = None,
                    compressed_size: int = 0, ratio: float = 1.0, encrypted: bool = False) -> None:
        key = str(path.resolve())
        if key in self._artifacts:
            meta = self._artifacts[key]
            meta.tier = tier.value
            if compressed_path:
                meta.compressed_path = compressed_path
            meta.compressed_size = compressed_size
            meta.compression_ratio = ratio
            meta.encrypted = encrypted
            self._dirty = True

    def remove(self, path: Path) -> None:
        key = str(path.resolve())
        if self._artifacts.pop(key, None) is not None:
            self._dirty = True

    def all_artifacts(self) -> list[ArtifactMeta]:
        return list(self._artifacts.values())

    def by_tier(self, tier: Tier) -> list[ArtifactMeta]:
        return [a for a in self._artifacts.values() if a.tier == tier.value]

    def candidates_for_warm(self, age_hours: float, idle_hours: float,
                            min_size: int) -> list[ArtifactMeta]:
        """Find hot artifacts eligible for warm tier."""
        return [
            a for a in self._artifacts.values()
            if a.tier == Tier.HOT.value
            and a.age_hours >= age_hours
            and a.idle_hours >= idle_hours
            and a.original_size >= min_size
        ]

    def candidates_for_cold(self, age_hours: float, idle_hours: float) -> list[ArtifactMeta]:
        """Find warm artifacts eligible for cold tier."""
        return [
            a for a in self._artifacts.values()
            if a.tier == Tier.WARM.value
            and a.age_hours >= age_hours
            and a.idle_hours >= idle_hours
        ]

    def candidates_for_frozen(self, age_hours: float, idle_hours: float) -> list[ArtifactMeta]:
        """Find cold artifacts eligible for frozen tier (deep archive)."""
        return [
            a for a in self._artifacts.values()
            if a.tier == Tier.COLD.value
            and a.age_hours >= age_hours
            and a.idle_hours >= idle_hours
        ]

    def stats(self) -> dict:
        """Return summary statistics in a single pass over artifacts."""
        counts: dict[str, int] = {"hot": 0, "warm": 0, "cold": 0, "frozen": 0}
        total_original = 0
        total_compressed = 0
        total_hot_bytes = 0

        for a in self._artifacts.values():
            counts[a.tier] = counts.get(a.tier, 0) + 1
            total_original += a.original_size
            if a.compressed_size > 0:
                total_compressed += a.compressed_size
            if a.tier == Tier.HOT.value:
                total_hot_bytes += a.original_size

        return {
            "total_artifacts": len(self._artifacts),
            "hot_count": counts.get("hot", 0),
            "warm_count": counts.get("warm", 0),
            "cold_count": counts.get("cold", 0),
            "frozen_count": counts.get("frozen", 0),
            "total_original_bytes": total_original,
            "total_compressed_bytes": total_compressed,
            "total_hot_bytes": total_hot_bytes,
            "overall_ratio": round(total_original / total_compressed, 2) if total_compressed > 0 else 1.0,
            # Space saved = sum of (original - compressed) for each compressed artifact
            "space_saved_bytes": (total_original - total_hot_bytes) - total_compressed if total_compressed > 0 else 0,
        }


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file for integrity verification.

    Delegates to fileutil.compute_file_hash for the single canonical
    implementation. This wrapper exists for backward compatibility.
    """
    from .fileutil import compute_file_hash
    return compute_file_hash(filepath)

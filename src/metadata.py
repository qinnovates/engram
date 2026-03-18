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

import hashlib
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
                    # Filter to known fields only — prevents crash on unknown keys
                    # and avoids silent state wipe from TypeError
                    filtered = {k: v for k, v in val.items()
                                if k in self._KNOWN_FIELDS}
                    self._artifacts[key] = ArtifactMeta(**filtered)
            except json.JSONDecodeError:
                self._artifacts = {}

    def save(self) -> None:
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": time.time(),
            "artifact_count": len(self._artifacts),
            "artifacts": {k: asdict(v) for k, v in self._artifacts.items()},
        }
        # Atomic write with restricted permissions (0600)
        import os
        tmp = self.db_path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        tmp.rename(self.db_path)

    def register(self, path: Path) -> ArtifactMeta:
        """Register or update a file in the metadata store."""
        key = str(path.resolve())
        now = time.time()

        if key in self._artifacts:
            meta = self._artifacts[key]
            # Update access time
            meta.last_accessed = now
            if path.exists():
                stat = path.stat()
                meta.last_modified = stat.st_mtime
                meta.original_size = stat.st_size
            return meta

        # New artifact
        if path.exists():
            stat = path.stat()
            meta = ArtifactMeta(
                path=key,
                tier=Tier.HOT.value,
                created_at=stat.st_ctime,
                last_accessed=now,
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
        return meta

    def get(self, path: Path) -> Optional[ArtifactMeta]:
        return self._artifacts.get(str(path.resolve()))

    def touch(self, path: Path) -> None:
        """Update last_accessed timestamp (called on decompress/read)."""
        key = str(path.resolve())
        if key in self._artifacts:
            self._artifacts[key].last_accessed = time.time()

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

    def remove(self, path: Path) -> None:
        key = str(path.resolve())
        self._artifacts.pop(key, None)

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
        """Return summary statistics."""
        hot = self.by_tier(Tier.HOT)
        warm = self.by_tier(Tier.WARM)
        cold = self.by_tier(Tier.COLD)
        frozen = self.by_tier(Tier.FROZEN)

        total_original = sum(a.original_size for a in self._artifacts.values())
        total_compressed = sum(
            a.compressed_size for a in self._artifacts.values()
            if a.compressed_size > 0
        )
        total_hot_size = sum(a.original_size for a in hot)

        return {
            "total_artifacts": len(self._artifacts),
            "hot_count": len(hot),
            "warm_count": len(warm),
            "cold_count": len(cold),
            "frozen_count": len(frozen),
            "total_original_bytes": total_original,
            "total_compressed_bytes": total_compressed,
            "total_hot_bytes": total_hot_size,
            "overall_ratio": round(total_original / total_compressed, 2) if total_compressed > 0 else 1.0,
            "space_saved_bytes": total_original - total_compressed - total_hot_size if total_compressed > 0 else 0,
        }


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

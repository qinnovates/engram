"""
Shared file utilities — atomic writes, path containment, constants.

Extracted from 6+ duplicate implementations across the codebase.
Every file I/O operation that touches security-sensitive data should
use these instead of raw open/write/rename.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


# --- Shared constants ---

# File extensions to skip during scanning (already compressed/processed)
SKIP_SUFFIXES = frozenset({".zst", ".encf", ".tmp", ".parquet", ".gz"})

# Maximum content to read for indexing (100KB — long tail adds noise)
MAX_INDEX_BYTES = 102_400

# Maximum decompression output (500MB — bomb protection)
MAX_DECOMPRESS_BYTES = 500 * 1024 * 1024

# Default engram directory
ENGRAM_DIR = "~/.engram"


def atomic_write_text(path: Path, content: str,
                      permissions: int = 0o600) -> None:
    """Write text atomically with restricted permissions.

    Creates a temp file with the target permissions, writes content,
    then atomically renames to the target path. If the write fails,
    the temp file is cleaned up and the original is untouched.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        suffix=".tmp", dir=str(path.parent), prefix=".engram-"
    )
    os.fchmod(fd, permissions)  # SECURITY: restrict BEFORE writing content
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        tmp.rename(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


def atomic_write_bytes(path: Path, content: bytes,
                       permissions: int = 0o600) -> None:
    """Write bytes atomically with restricted permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        suffix=".tmp", dir=str(path.parent), prefix=".engram-"
    )
    os.fchmod(fd, permissions)  # SECURITY: restrict BEFORE writing content
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        tmp.rename(path)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


def is_path_under(child: Path, root: Path) -> bool:
    """Check if a resolved path is contained within a root directory.

    Both paths are resolved before comparison to handle symlinks.
    Returns False if child escapes root via traversal.
    """
    try:
        child.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hex digest of a file using chunked reads.

    Single canonical implementation — use this instead of inlining
    the hash pattern. Returns 64-char hex string.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    """SHA-256 hex digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()

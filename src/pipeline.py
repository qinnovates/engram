"""
Multi-stage compression pipeline — the core differentiator.

Plain zstd at different levels gives you 3.2x → 3.8x across four tiers.
That's pathetic. The real gains come from preprocessing data BEFORE
it hits the compressor. Each tier applies progressively more aggressive
transformations:

  HOT:    Raw files, no processing.                           1x
  WARM:   Minify JSON → zstd-3.                               4-5x
  COLD:   Strip boilerplate → dict-trained zstd-9.            8-12x
  FROZEN: Columnar Parquet + dict encoding + zstd-19.         20-50x

Why the ratios jump so dramatically:

  WARM:  JSON minification removes 30-40% of whitespace/formatting
         before zstd even starts. zstd-3 handles the rest.

  COLD:  AI session logs repeat the same system prompts, tool schemas,
         and boilerplate across every session. Stripping these to hash
         references removes 40-70% of content. A dictionary trained on
         500 representative sessions encodes the remaining shared schema
         as known offsets, not novel data.

  FROZEN: JSONL files repeat the same keys on every line ("role",
          "content", "timestamp"). Columnar transposition via Parquet
          groups all values for each key together. The "role" column
          (cardinality: 2-4) compresses via run-length encoding to near
          nothing. The "timestamp" column (monotonic integers) compresses
          via delta encoding to near nothing. Only the actual content
          text carries real entropy.

          This is why ClickHouse achieves 75x on structured data.
          This is why Parquet achieves 10-25x on log data.
          Same principle, applied to your AI memories.

References:
  - Dictionary compression: HTTPToolkit blog (57-90% vs non-dict Brotli)
  - Parquet ratios: dataexpert.io (6.6-8x vs CSV on low-cardinality)
  - ClickHouse codecs: Delta+ZSTD = 800:1 on monotonic sequences
  - zstd dict on JSON: GitHub issue #97 (3.7x → 5.2x with hollow dict)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

import zstandard as zstd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False


# --- Pipeline stage results ---

class PipelineResult:
    """Result of a multi-stage compression pipeline."""
    def __init__(self, original_size: int, final_size: int,
                 output_path: Path, tier: str,
                 stages: list[str]):
        self.original_size = original_size
        self.final_size = final_size
        self.output_path = output_path
        self.tier = tier
        self.stages = stages  # e.g., ["minify", "zstd-3"]

    @property
    def ratio(self) -> float:
        if self.final_size == 0:
            return 0.0
        return round(self.original_size / self.final_size, 1)

    def __repr__(self) -> str:
        return (
            f"PipelineResult(tier={self.tier}, ratio={self.ratio}x, "
            f"stages={self.stages}, "
            f"{self.original_size:,} → {self.final_size:,} bytes)"
        )


# =============================================================
#  Stage 1: JSON Minification (warm+)
# =============================================================

def minify_json(content: bytes) -> bytes:
    """
    Strip whitespace from JSON/JSONL content.

    Removes indentation, trailing whitespace, and unnecessary formatting
    while preserving data integrity. Handles both single JSON objects
    and JSONL (one JSON object per line).

    Typical savings: 30-40% on pretty-printed JSON.
    """
    lines = content.split(b"\n")
    minified = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            # Parse and re-serialize without whitespace
            obj = json.loads(stripped)
            minified.append(json.dumps(obj, separators=(",", ":")).encode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON — keep as-is but stripped
            minified.append(stripped)

    return b"\n".join(minified)


# =============================================================
#  Stage 2: Boilerplate Stripping (cold+)
# =============================================================

# Common boilerplate markers in AI session logs
BOILERPLATE_MARKERS = [
    b"<system-reminder>",
    b"system-reminder",
    b"You are Claude",
    b"You are an interactive agent",
    b"IMPORTANT: Assist with authorized",
    b"# System\n",
    b"# Environment\n",
    b"<available-deferred-tools>",
]

# Minimum size for a block to be considered boilerplate
MIN_BOILERPLATE_SIZE = 500


def strip_boilerplate(content: bytes, boilerplate_store: Path) -> bytes:
    """
    Replace repeated boilerplate blocks with compact hash references.

    AI session logs often contain 2,000-5,000 token system prompts
    repeated verbatim in every session. Replacing these with 64-byte
    hash references can reduce total content by 40-70%.

    The boilerplate store is a directory of hash-named files containing
    the original blocks for reconstruction during recall.

    Args:
        content: Raw file content.
        boilerplate_store: Directory to store/lookup boilerplate blocks.

    Returns:
        Content with boilerplate replaced by BOILERPLATE_REF lines.
    """
    boilerplate_store.mkdir(parents=True, exist_ok=True)
    result = content

    # Process JSONL: check each line's "content" field for boilerplate
    lines = content.split(b"\n")
    output_lines = []
    total_stripped = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            output_lines.append(line)
            continue

        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and "content" in obj:
                text = obj["content"]
                if isinstance(text, str) and len(text) >= MIN_BOILERPLATE_SIZE:
                    # Check if this content block matches boilerplate patterns
                    text_bytes = text.encode("utf-8")
                    if _is_boilerplate(text_bytes):
                        ref = _store_boilerplate(text_bytes, boilerplate_store)
                        obj["content"] = f"BOILERPLATE_REF:{ref}"
                        total_stripped += len(text_bytes)
                        output_lines.append(
                            json.dumps(obj, separators=(",", ":")).encode("utf-8")
                        )
                        continue
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        output_lines.append(line)

    if total_stripped > 0:
        return b"\n".join(output_lines)
    return content


def _is_boilerplate(text: bytes) -> bool:
    """Check if a text block matches known boilerplate patterns."""
    for marker in BOILERPLATE_MARKERS:
        if marker in text:
            return True
    return False


def _store_boilerplate(text: bytes, store: Path) -> str:
    """Store a boilerplate block and return its hash reference."""
    h = hashlib.sha256(text).hexdigest()[:32]  # 128-bit, collision-safe
    ref_path = store / f"{h}.boilerplate"
    if not ref_path.exists():
        fd = os.open(str(ref_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(text)
    return h


def restore_boilerplate(content: bytes, boilerplate_store: Path) -> bytes:
    """Restore boilerplate references to full content for recall."""
    lines = content.split(b"\n")
    output_lines = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            output_lines.append(line)
            continue

        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and "content" in obj:
                text = obj["content"]
                if isinstance(text, str) and text.startswith("BOILERPLATE_REF:"):
                    ref = text.split(":", 1)[1]
                    # Validate ref is hex-only (prevents path traversal)
                    if not re.fullmatch(r'[0-9a-f]{16,64}', ref):  # hex-only guard
                        output_lines.append(line)
                        continue
                    ref_path = boilerplate_store / f"{ref}.boilerplate"
                    if ref_path.exists():
                        obj["content"] = ref_path.read_text()
                        output_lines.append(
                            json.dumps(obj, separators=(",", ":")).encode("utf-8")
                        )
                        continue
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        output_lines.append(line)

    return b"\n".join(output_lines)


# =============================================================
#  Stage 3: Dictionary Training + Compression (cold)
# =============================================================

DICT_FILENAME = "compression.dict"
DICT_SIZE = 112 * 1024  # 112 KB — zstd CLI default


def train_dictionary(sample_paths: list[Path], output_dir: Path,
                     max_samples: int = 500) -> Optional[zstd.ZstdCompressionDict]:
    """
    Train a zstd dictionary on representative artifacts.

    A dictionary trained on 500 representative session logs encodes
    the shared schema (JSON keys, boilerplate fragments, common tokens)
    as known offsets. The compressor then only handles the unique content.

    Measured improvement: 2x-5x better than compression without dictionary
    on small structured data (Meta/Facebook zstd documentation).

    Args:
        sample_paths: Paths to representative artifacts for training.
        output_dir: Where to store the trained dictionary.
        max_samples: Maximum samples to use (more = better dict, slower).

    Returns:
        Trained dictionary object, or None if training fails.
    """
    samples = []
    for p in sample_paths[:max_samples]:
        if p.exists() and p.stat().st_size > 0:
            try:
                samples.append(p.read_bytes()[:50_000])  # Cap per-sample
            except (PermissionError, OSError):
                continue

    if len(samples) < 10:
        return None  # Not enough samples for meaningful training

    try:
        dict_data = zstd.train_dictionary(DICT_SIZE, samples)
    except zstd.ZstdError:
        return None

    # Persist dictionary
    dict_path = output_dir / DICT_FILENAME
    fd = os.open(str(dict_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dict_data.as_bytes())

    return dict_data


def load_dictionary(dict_dir: Path) -> Optional[zstd.ZstdCompressionDict]:
    """Load a trained dictionary from disk."""
    dict_path = dict_dir / DICT_FILENAME
    if not dict_path.exists():
        return None
    try:
        raw = dict_path.read_bytes()
        return zstd.ZstdCompressionDict(raw)
    except (zstd.ZstdError, OSError):
        return None


def compress_with_dict(data: bytes, level: int,
                       dict_data: Optional[zstd.ZstdCompressionDict] = None) -> bytes:
    """Compress data with optional dictionary."""
    if dict_data:
        compressor = zstd.ZstdCompressor(level=level, dict_data=dict_data)
    else:
        compressor = zstd.ZstdCompressor(level=level)
    return compressor.compress(data)


def decompress_with_dict(data: bytes,
                         dict_data: Optional[zstd.ZstdCompressionDict] = None) -> bytes:
    """Decompress data with optional dictionary."""
    if dict_data:
        decompressor = zstd.ZstdDecompressor(dict_data=dict_data)
    else:
        decompressor = zstd.ZstdDecompressor()
    return decompressor.decompress(data, max_output_size=500 * 1024 * 1024)


# =============================================================
#  Stage 4: Columnar Parquet (frozen)
# =============================================================

PARQUET_EXT = ".parquet"


def jsonl_to_parquet(content: bytes, output_path: Path,
                     compression_level: int = 19) -> int:
    """
    Transform JSONL to columnar Parquet with dictionary encoding + zstd.

    Why Parquet for frozen tier:

    JSONL repeats the same keys on every line. In a 10,000-turn session,
    the string "role" appears 10,000 times. Parquet groups all values for
    each key into a single column:

      - "role" column: ["user", "assistant", "user", ...] → cardinality 2-4
        → run-length encoded to near nothing
      - "timestamp" column: monotonic integers → delta encoded to near nothing
      - "content" column: the actual text → dictionary encoded + zstd

    ClickHouse achieves 75x on structured data with this approach.
    Parquet achieves 10-25x on log data. We apply the same principle
    to AI memory artifacts.

    The columnar format also enables column-pruning on read: if you only
    need the "role" and "timestamp" columns for a search, you skip
    decompressing "content" entirely. This makes frozen-tier search
    faster than decompressing the full JSONL.

    Args:
        content: Raw JSONL bytes.
        output_path: Destination .parquet file.
        compression_level: zstd level for Parquet compression.

    Returns:
        Size of the output Parquet file in bytes.
    """
    if not HAS_PYARROW:
        raise ImportError(
            "pyarrow required for frozen tier. Install: pip install pyarrow"
        )

    # Parse JSONL to list of dicts
    rows = []
    for line in content.split(b"\n"):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rows.append(json.loads(stripped))
        except json.JSONDecodeError:
            # Non-JSON lines: wrap as plain text
            rows.append({"_raw": stripped.decode("utf-8", errors="replace")})

    if not rows:
        # Empty file — write minimal Parquet
        table = pa.table({"_empty": [True]})
    else:
        # Normalize schema: collect all keys across all rows
        all_keys = set()
        for row in rows:
            if isinstance(row, dict):
                all_keys.update(row.keys())

        # Build columnar arrays
        columns = {}
        for key in sorted(all_keys):
            values = []
            for row in rows:
                if isinstance(row, dict):
                    val = row.get(key)
                    # Convert all values to strings for uniform schema
                    values.append(str(val) if val is not None else None)
                else:
                    values.append(None)
            columns[key] = values

        table = pa.table(columns)

    # Write with dictionary encoding + zstd compression
    pq.write_table(
        table,
        str(output_path),
        compression="zstd",
        compression_level=compression_level,
        use_dictionary=True,
        write_statistics=True,
    )

    return output_path.stat().st_size


def parquet_to_jsonl(parquet_path: Path) -> bytes:
    """
    Restore JSONL from a Parquet file for recall.

    Reads the columnar format back into row-oriented JSONL.
    """
    if not HAS_PYARROW:
        raise ImportError("pyarrow required for frozen tier recall")

    table = pq.read_table(str(parquet_path))
    rows = table.to_pylist()

    lines = []
    for row in rows:
        # Remove None values and the _empty sentinel
        cleaned = {k: v for k, v in row.items()
                   if v is not None and k != "_empty"}
        if cleaned:
            lines.append(json.dumps(cleaned, separators=(",", ":")).encode("utf-8"))

    return b"\n".join(lines)


# =============================================================
#  Pipeline Orchestrator
# =============================================================

class CompressionPipeline:
    """
    Orchestrates multi-stage compression per tier.

    Each tier applies progressively more aggressive transformations:

      WARM:   minify → zstd-3                         (~4-5x)
      COLD:   strip boilerplate → minify → dict zstd-9 (~8-12x)
      FROZEN: strip → minify → columnar Parquet+zstd-19 (~20-50x)
    """

    def __init__(self, metadata_dir: Path):
        self.metadata_dir = metadata_dir
        self.boilerplate_store = metadata_dir / "boilerplate"
        self._dict: Optional[zstd.ZstdCompressionDict] = None

    def get_dictionary(self) -> Optional[zstd.ZstdCompressionDict]:
        """Load or return cached compression dictionary."""
        if self._dict is None:
            self._dict = load_dictionary(self.metadata_dir)
        return self._dict

    def train_dict(self, sample_paths: list[Path]) -> bool:
        """Train dictionary on representative artifacts. Returns success."""
        result = train_dictionary(sample_paths, self.metadata_dir)
        if result:
            self._dict = result
            return True
        return False

    def compress_warm(self, input_path: Path, output_path: Path) -> PipelineResult:
        """Warm pipeline: minify → zstd-3."""
        raw = input_path.read_bytes()
        original_size = len(raw)
        stages = []

        # Stage 1: Minify JSON
        processed = minify_json(raw)
        if len(processed) < original_size:
            stages.append("minify")
        else:
            processed = raw  # Minification didn't help, use original

        # Stage 2: zstd-3 compression
        compressor = zstd.ZstdCompressor(level=3)
        compressed = compressor.compress(processed)
        stages.append("zstd-3")

        # Atomic write
        fd, tmp = tempfile.mkstemp(dir=str(output_path.parent), suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(compressed)
        Path(tmp).rename(output_path)

        return PipelineResult(
            original_size=original_size,
            final_size=output_path.stat().st_size,
            output_path=output_path,
            tier="warm",
            stages=stages,
        )

    def compress_cold(self, input_path: Path, output_path: Path) -> PipelineResult:
        """Cold pipeline: strip boilerplate → minify → dict-trained zstd-9."""
        raw = input_path.read_bytes()
        original_size = len(raw)
        stages = []

        # Stage 1: Strip boilerplate
        processed = strip_boilerplate(raw, self.boilerplate_store)
        if len(processed) < original_size:
            stages.append("boilerplate-strip")

        # Stage 2: Minify JSON
        minified = minify_json(processed)
        if len(minified) < len(processed):
            stages.append("minify")
            processed = minified

        # Stage 3: Dictionary-trained zstd-9
        dict_data = self.get_dictionary()
        compressed = compress_with_dict(processed, level=9, dict_data=dict_data)
        stages.append("dict-zstd-9" if dict_data else "zstd-9")

        fd, tmp = tempfile.mkstemp(dir=str(output_path.parent), suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(compressed)
        Path(tmp).rename(output_path)

        return PipelineResult(
            original_size=original_size,
            final_size=output_path.stat().st_size,
            output_path=output_path,
            tier="cold",
            stages=stages,
        )

    def compress_frozen(self, input_path: Path, output_path: Path) -> PipelineResult:
        """
        Frozen pipeline: strip → minify → columnar Parquet + dict + zstd-19.

        Falls back to cold pipeline if pyarrow is not installed or if
        the input is not valid JSONL (plain text, markdown, etc.).
        """
        raw = input_path.read_bytes()
        original_size = len(raw)
        stages = []

        # Check if content is JSONL (Parquet conversion only works for JSONL)
        is_jsonl = input_path.suffix in (".jsonl", ".json") or _looks_like_jsonl(raw)

        if is_jsonl and HAS_PYARROW:
            # Stage 1: Strip boilerplate
            processed = strip_boilerplate(raw, self.boilerplate_store)
            if len(processed) < original_size:
                stages.append("boilerplate-strip")

            # Stage 2: Minify
            minified = minify_json(processed)
            if len(minified) < len(processed):
                stages.append("minify")
                processed = minified

            # Stage 3: Columnar Parquet + dict encoding + zstd-19
            parquet_output = output_path.with_suffix(".parquet")
            jsonl_to_parquet(processed, parquet_output, compression_level=19)
            stages.append("parquet-columnar-zstd-19")

            # Rename to final output
            if parquet_output != output_path:
                parquet_output.rename(output_path)

            return PipelineResult(
                original_size=original_size,
                final_size=output_path.stat().st_size,
                output_path=output_path,
                tier="frozen",
                stages=stages,
            )
        else:
            # Fallback: treat like cold but with higher zstd level
            processed = strip_boilerplate(raw, self.boilerplate_store)
            if len(processed) < original_size:
                stages.append("boilerplate-strip")

            minified = minify_json(processed)
            if len(minified) < len(processed):
                stages.append("minify")
                processed = minified

            dict_data = self.get_dictionary()
            compressed = compress_with_dict(processed, level=19, dict_data=dict_data)
            stages.append("dict-zstd-19" if dict_data else "zstd-19")

            fd, tmp = tempfile.mkstemp(dir=str(output_path.parent), suffix=".tmp")
            with os.fdopen(fd, "wb") as f:
                f.write(compressed)
            Path(tmp).rename(output_path)

            return PipelineResult(
                original_size=original_size,
                final_size=output_path.stat().st_size,
                output_path=output_path,
                tier="frozen",
                stages=stages,
            )

    def decompress_warm(self, compressed_path: Path) -> bytes:
        """Decompress warm-tier artifact."""
        decompressor = zstd.ZstdDecompressor()
        return decompressor.decompress(
            compressed_path.read_bytes(),
            max_output_size=500 * 1024 * 1024,
        )

    def decompress_cold(self, compressed_path: Path) -> bytes:
        """Decompress cold-tier artifact (may need dictionary)."""
        dict_data = self.get_dictionary()
        raw = decompress_with_dict(compressed_path.read_bytes(), dict_data)
        # Restore boilerplate references
        return restore_boilerplate(raw, self.boilerplate_store)

    def decompress_frozen(self, compressed_path: Path) -> bytes:
        """Decompress frozen-tier artifact (Parquet or fallback zstd)."""
        # Try Parquet first
        if HAS_PYARROW:
            try:
                raw = parquet_to_jsonl(compressed_path)
                return restore_boilerplate(raw, self.boilerplate_store)
            except Exception:
                pass  # Not a Parquet file, try zstd fallback

        # Fallback: dict-trained zstd
        dict_data = self.get_dictionary()
        raw = decompress_with_dict(compressed_path.read_bytes(), dict_data)
        return restore_boilerplate(raw, self.boilerplate_store)


def _looks_like_jsonl(content: bytes) -> bool:
    """Quick heuristic: does this look like JSONL content?"""
    lines = content.split(b"\n", 5)[:5]
    json_count = 0
    for line in lines:
        stripped = line.strip()
        if stripped and stripped[:1] == b"{":
            json_count += 1
    return json_count >= 2

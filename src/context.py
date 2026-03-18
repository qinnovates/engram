"""
Context window enhancement layer.

This is the bridge between compressed storage and AI assistant context injection.
Without this, the engine is just a storage optimizer. With this, it becomes
a memory system that makes AI assistants smarter across sessions.

Architecture (modeled after Elasticsearch's searchable snapshots):
  - HOT tier: full content loaded directly into context
  - WARM tier: semantic summary loaded; full content on demand
  - COLD tier: index entry only; summary then full content on demand

Progressive recall (like ELK's partially mounted frozen tier):
  1. Index scan — match query against keyword/semantic index (no decompression)
  2. Summary load — decompress and return the summary only (~10-20% of tokens)
  3. Full recall — decompress entire artifact (only when summary isn't enough)

This is AI-agnostic: returns plain text that any assistant can consume.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .metadata import MetadataStore, ArtifactMeta


# --- Default context budget (in approximate characters) ---
# Most models: 1 token ≈ 4 chars. 128K context ≈ 512K chars.
# Reserve 75% for conversation, 25% for memory injection.
DEFAULT_CONTEXT_BUDGET_CHARS = 128_000  # ~32K tokens


@dataclass
class ArtifactSummary:
    """Compact representation of an artifact for context injection."""
    path: str
    tier: str
    summary: str                     # Human-readable summary of content
    keywords: list[str] = field(default_factory=list)
    line_count: int = 0
    char_count: int = 0
    created_at: float = 0.0
    last_accessed: float = 0.0
    relevance_score: float = 0.0     # 0.0-1.0, set by relevance scoring

    @property
    def age_days(self) -> float:
        return (time.time() - self.created_at) / 86400

    @property
    def idle_days(self) -> float:
        return (time.time() - self.last_accessed) / 86400

    @property
    def recall_hint(self) -> str:
        """Human-readable hint about what recall from this tier involves."""
        hints = {
            "hot": "instant access",
            "warm": "quick recall (~10ms, light decompression)",
            "cold": "slower recall (~500ms, dictionary decompression, may need encryption key)",
            "frozen": "slowest recall (~5-10s, Parquet restoration, may need encryption key)",
        }
        return hints.get(self.tier, "unknown tier")

    def to_context_line(self) -> str:
        """Single-line representation for context injection."""
        tier_icon = {"hot": "●", "warm": "◐", "cold": "○", "frozen": "◌"}.get(self.tier, "?")
        age = f"{self.age_days:.0f}d"
        return f"{tier_icon} [{self.tier}] {self.path} ({self.char_count} chars, {age} old) — {self.summary}"

    def to_context_block(self) -> str:
        """Multi-line representation with keywords and recall hint."""
        lines = [self.to_context_line()]
        if self.tier in ("cold", "frozen"):
            lines.append(f"  ⏱ Recall: {self.recall_hint}")
        if self.keywords:
            lines.append(f"  Keywords: {', '.join(self.keywords[:10])}")
        return "\n".join(lines)


@dataclass
class ContextBudget:
    """Tracks how much context space remains for memory injection."""
    total_chars: int = DEFAULT_CONTEXT_BUDGET_CHARS
    used_chars: int = 0

    @property
    def remaining_chars(self) -> int:
        return max(0, self.total_chars - self.used_chars)

    @property
    def remaining_tokens_approx(self) -> int:
        return self.remaining_chars // 4

    def can_fit(self, text: str) -> bool:
        return len(text) <= self.remaining_chars

    def consume(self, text: str) -> bool:
        """Try to consume budget for text. Returns True if it fit."""
        if self.can_fit(text):
            self.used_chars += len(text)
            return True
        return False

    @property
    def utilization_pct(self) -> float:
        if self.total_chars == 0:
            return 100.0
        return round(self.used_chars / self.total_chars * 100, 1)


class SemanticIndex:
    """
    Keyword-based index of artifact contents for fast relevance matching.

    This is the equivalent of Elasticsearch's inverted index — it lets us
    find relevant artifacts without decompressing them.

    Stored alongside the metadata registry. Updated when artifacts are
    first registered (hot) or when summaries are generated.
    """

    def __init__(self, index_dir: Path):
        self.index_path = index_dir / "semantic-index.json"
        self._entries: dict[str, ArtifactSummary] = {}
        self._dirty: bool = False
        self._load()

    # Known fields — filter out unknown keys to prevent injection/crash
    _KNOWN_FIELDS = {
        "path", "tier", "summary", "keywords", "line_count", "char_count",
        "created_at", "last_accessed", "relevance_score",
    }

    def _load(self) -> None:
        if self.index_path.exists():
            try:
                with open(self.index_path) as f:
                    data = json.load(f)
                for key, val in data.get("entries", {}).items():
                    filtered = {k: v for k, v in val.items()
                                if k in self._KNOWN_FIELDS}
                    # Sanitize summary — strip potential prompt injection
                    if "summary" in filtered:
                        filtered["summary"] = self._sanitize_summary(
                            filtered["summary"])
                    self._entries[key] = ArtifactSummary(**filtered)
            except json.JSONDecodeError:
                self._entries = {}

    @staticmethod
    def _sanitize_summary(summary: str) -> str:
        """Strip potential prompt injection patterns from summaries."""
        if not isinstance(summary, str):
            return ""
        # Limit length
        summary = summary[:200]
        # Strip markdown headers that could inject AI instructions
        lines = []
        for line in summary.split("\n"):
            stripped = line.strip().lower()
            # Block common injection patterns
            if any(p in stripped for p in [
                "system:", "assistant:", "ignore previous",
                "you are now", "disregard", "forget your",
            ]):
                continue
            lines.append(line)
        return " ".join(lines).strip()

    def save(self, force: bool = False) -> None:
        if not force and not self._dirty:
            return
        import os
        from dataclasses import asdict
        payload = {
            "version": 1,
            "updated_at": time.time(),
            "entry_count": len(self._entries),
            "entries": {k: asdict(v) for k, v in self._entries.items()},
        }
        tmp = self.index_path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        tmp.rename(self.index_path)
        self._dirty = False

    def index_artifact(self, path: Path, content: str, meta: ArtifactMeta) -> ArtifactSummary:
        """
        Index a file's content: extract keywords and generate summary.

        This runs at registration time (hot tier) so we have the index
        available even after the artifact moves to warm/cold.
        """
        key = str(path.resolve())

        # Cap content for keyword extraction (100KB is sufficient;
        # the long tail adds noise, not signal — and prevents OOM on large files)
        MAX_INDEX_CHARS = 102_400
        index_content = content[:MAX_INDEX_CHARS] if len(content) > MAX_INDEX_CHARS else content

        keywords = self._extract_keywords(index_content)
        summary = self._generate_summary(index_content, path)

        entry = ArtifactSummary(
            path=str(path),
            tier=meta.tier,
            summary=summary,
            keywords=keywords,
            line_count=content.count("\n") + 1,
            char_count=len(content),
            created_at=meta.created_at,
            last_accessed=meta.last_accessed,
        )

        self._entries[key] = entry
        self._dirty = True
        return entry

    def update_tier(self, path: Path, tier: str) -> None:
        """Update the tier field when an artifact moves between tiers."""
        key = str(path.resolve())
        if key in self._entries:
            self._entries[key].tier = tier
            self._dirty = True

    def search(self, query: str, max_results: int = 10) -> list[ArtifactSummary]:
        """
        Search the index for artifacts matching a query.

        Uses keyword overlap scoring — no ML embeddings needed,
        keeping this AI-agnostic and dependency-free.

        Args:
            query: Search query (natural language or keywords).
            max_results: Maximum results to return.

        Returns:
            List of ArtifactSummary sorted by relevance score.
        """
        query_terms = self._tokenize(query.lower())
        if not query_terms:
            return []

        scored: list[ArtifactSummary] = []

        for entry in self._entries.values():
            score = self._compute_relevance(query_terms, entry)
            if score > 0:
                entry.relevance_score = score
                scored.append(entry)

        # Sort by relevance (descending), then by recency (descending)
        scored.sort(key=lambda e: (e.relevance_score, -e.idle_days), reverse=True)
        return scored[:max_results]

    def get(self, path: Path) -> Optional[ArtifactSummary]:
        return self._entries.get(str(path.resolve()))

    def all_entries(self) -> list[ArtifactSummary]:
        return list(self._entries.values())

    def _compute_relevance(self, query_terms: set[str], entry: ArtifactSummary) -> float:
        """
        Compute relevance score (0.0-1.0) for an artifact against query terms.

        Scoring factors:
          - Keyword overlap (primary signal)
          - Summary text match (secondary)
          - Recency boost (recent artifacts score higher)
          - Path match (filename contains query term)
        """
        if not query_terms:
            return 0.0

        entry_keywords = set(k.lower() for k in entry.keywords)
        summary_terms = self._tokenize(entry.summary.lower())
        path_terms = self._tokenize(Path(entry.path).stem.lower())

        # Keyword overlap: strongest signal
        keyword_overlap = len(query_terms & entry_keywords)
        keyword_score = keyword_overlap / len(query_terms) if query_terms else 0

        # Summary match
        summary_overlap = len(query_terms & summary_terms)
        summary_score = summary_overlap / len(query_terms) if query_terms else 0

        # Path match
        path_overlap = len(query_terms & path_terms)
        path_score = path_overlap / len(query_terms) if query_terms else 0

        # Recency boost: decay over 30 days
        recency = max(0, 1.0 - (entry.idle_days / 30))

        # Weighted combination
        score = (
            keyword_score * 0.5 +
            summary_score * 0.3 +
            path_score * 0.1 +
            recency * 0.1
        )

        return min(1.0, score)

    def _extract_keywords(self, content: str) -> list[str]:
        """
        Extract keywords from content using frequency analysis.

        No ML dependencies — pure statistical extraction.
        Filters out common stopwords and short tokens.
        """
        tokens = self._tokenize(content.lower())

        # Count frequencies
        freq: dict[str, int] = {}
        for token in tokens:
            if token not in _STOPWORDS and len(token) > 2:
                freq[token] = freq.get(token, 0) + 1

        # Return top keywords by frequency
        sorted_tokens = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        return [token for token, _ in sorted_tokens[:30]]

    def _generate_summary(self, content: str, path: Path) -> str:
        """
        Generate a compact summary of file content.

        Strategy varies by file type:
          - JSONL: count entries, extract common fields
          - Markdown: use first heading + first paragraph
          - JSON: describe top-level structure
          - Plain text: first meaningful line
        """
        name = path.name.lower()

        if name.endswith(".jsonl"):
            return self._summarize_jsonl(content)
        elif name.endswith(".md"):
            return self._summarize_markdown(content)
        elif name.endswith(".json"):
            return self._summarize_json(content)
        else:
            return self._summarize_text(content)

    def _summarize_jsonl(self, content: str) -> str:
        lines = content.strip().split("\n")
        count = len(lines)
        # Try to identify the schema from first line
        try:
            first = json.loads(lines[0])
            keys = list(first.keys())[:5]
            return f"{count} entries, fields: {', '.join(keys)}"
        except (json.JSONDecodeError, IndexError):
            return f"{count} lines (JSONL)"

    def _summarize_markdown(self, content: str) -> str:
        lines = content.strip().split("\n")
        # Find first heading
        heading = ""
        for line in lines:
            if line.startswith("#"):
                heading = line.lstrip("#").strip()
                break
        # Find first non-empty, non-heading line
        body = ""
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("---"):
                body = stripped[:100]
                break
        if heading and body:
            return f"{heading}: {body}"
        return heading or body or "Empty markdown"

    def _summarize_json(self, content: str) -> str:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                keys = list(data.keys())[:5]
                return f"JSON object with keys: {', '.join(keys)}"
            elif isinstance(data, list):
                return f"JSON array with {len(data)} items"
            return f"JSON value: {type(data).__name__}"
        except json.JSONDecodeError:
            return "Invalid JSON"

    def _summarize_text(self, content: str) -> str:
        lines = content.strip().split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped and len(stripped) > 10:
                return stripped[:120]
        return f"{len(lines)} lines"

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Split text into lowercase alphanumeric tokens."""
        return set(re.findall(r'[a-z0-9]+', text.lower()))


class ContextBuilder:
    """
    Builds context payloads for AI assistant injection.

    This is the main interface AI assistants use to get relevant memory
    context. It handles budget management, progressive recall, and
    formatting.

    Usage flow:
      1. Assistant starts a session
      2. ContextBuilder.build_session_context(query) returns relevant memories
      3. Assistant includes the context in its prompt/system message
      4. If more detail needed, assistant calls recall_detail(path)
    """

    def __init__(self, index: SemanticIndex, metadata: MetadataStore,
                 budget: Optional[ContextBudget] = None):
        self.index = index
        self.metadata = metadata
        self.budget = budget or ContextBudget()

    def build_session_context(self, query: str = "",
                               max_entries: int = 20) -> str:
        """
        Build a context block for session injection.

        Progressive loading strategy (like ELK frozen tier):
          1. Always include hot-tier summaries (they're small and recent)
          2. Search warm/cold index for query-relevant entries
          3. Fill remaining budget with recency-sorted summaries

        Args:
            query: Optional query to bias relevance (e.g., current task description).
            max_entries: Maximum number of memory entries to include.

        Returns:
            Formatted context string ready for injection into AI prompt.
        """
        sections: list[str] = []

        # Header
        header = "## Memory Context (auto-loaded)\n"
        if not self.budget.consume(header):
            return ""
        sections.append(header)

        # Phase 1: Hot tier summaries (always included)
        hot_entries = [e for e in self.index.all_entries() if e.tier == "hot"]
        hot_entries.sort(key=lambda e: e.last_accessed, reverse=True)

        if hot_entries:
            hot_section = "### Recent (hot tier)\n"
            self.budget.consume(hot_section)
            sections.append(hot_section)

            for entry in hot_entries[:max_entries // 2]:
                line = entry.to_context_line() + "\n"
                if not self.budget.consume(line):
                    break
                sections.append(line)

        # Phase 2: Query-relevant entries from warm/cold
        if query:
            relevant = self.index.search(query, max_results=max_entries)
            # Filter out hot entries (already included)
            relevant = [e for e in relevant if e.tier != "hot"]

            if relevant:
                # Sanitize query before embedding in context output
                safe_query = re.sub(r'[\n\r#*`\[\]<>]', '', query[:50]).strip()
                rel_header = f"\n### Relevant to: \"{safe_query}\"\n"
                self.budget.consume(rel_header)
                sections.append(rel_header)

                for entry in relevant:
                    block = entry.to_context_block() + "\n"
                    if not self.budget.consume(block):
                        break
                    sections.append(block)

        # Phase 3: Fill remaining budget with warm-tier by recency
        warm_entries = [e for e in self.index.all_entries()
                        if e.tier == "warm" and e.relevance_score == 0]
        warm_entries.sort(key=lambda e: e.last_accessed, reverse=True)

        if warm_entries and self.budget.remaining_chars > 200:
            warm_header = "\n### Archived (warm tier)\n"
            self.budget.consume(warm_header)
            sections.append(warm_header)

            for entry in warm_entries[:5]:
                line = entry.to_context_line() + "\n"
                if not self.budget.consume(line):
                    break
                sections.append(line)

        # Footer with budget stats and tier access guide
        cold_count = sum(1 for e in self.index.all_entries() if e.tier == "cold")
        frozen_count = sum(1 for e in self.index.all_entries() if e.tier == "frozen")

        tier_note = ""
        if cold_count > 0 or frozen_count > 0:
            tier_note = (
                f"\n**Archived memories:** {cold_count} cold, {frozen_count} frozen. "
                f"These are indexed above (searchable by keyword) but compressed on disk. "
                f"To access full content, use `engram recall <path>`. "
                f"Cold recall takes ~500ms. Frozen recall takes ~5-10s. "
                f"If encryption is enabled, Touch ID or vault access may be required.\n"
            )

        footer = (
            f"\n---\n"
            f"Memory: {self.budget.utilization_pct}% of context budget used "
            f"(~{self.budget.remaining_tokens_approx:,} tokens remaining). "
            f"Use `engram recall <path>` for full content."
            f"{tier_note}\n"
        )
        self.budget.consume(footer)
        sections.append(footer)

        return "".join(sections)

    def recall_detail(self, path: Path) -> Optional[str]:
        """
        Get full content of an artifact for detailed context.

        This is the "click to expand" — the assistant asks for full
        content only when the summary isn't enough.

        For hot artifacts: reads directly.
        For warm/cold: requires decompression (handled by engine.recall()).

        Returns:
            Full text content, or None if not found.
        """
        resolved = path.resolve()

        # Try reading directly first (hot tier)
        if resolved.exists() and resolved.is_file():
            try:
                content = resolved.read_text(errors="replace")
                self.metadata.touch(resolved)
                return content
            except (PermissionError, OSError):
                return None

        return None  # Caller should use engine.recall() for warm/cold

    def get_context_stats(self) -> dict:
        """Return statistics about the context index."""
        entries = self.index.all_entries()
        return {
            "total_indexed": len(entries),
            "hot_entries": sum(1 for e in entries if e.tier == "hot"),
            "warm_entries": sum(1 for e in entries if e.tier == "warm"),
            "cold_entries": sum(1 for e in entries if e.tier == "cold"),
            "total_keywords": sum(len(e.keywords) for e in entries),
            "total_chars_indexed": sum(e.char_count for e in entries),
            "budget_used_pct": self.budget.utilization_pct,
            "budget_remaining_tokens": self.budget.remaining_tokens_approx,
        }


# --- Stopwords for keyword extraction ---
# Minimal set — we want domain terms to survive, not just nouns
_STOPWORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "has", "his", "how", "its", "may",
    "new", "now", "old", "see", "way", "who", "did", "get", "got", "let",
    "say", "she", "too", "use", "been", "call", "come", "each", "from",
    "have", "into", "just", "like", "long", "look", "make", "many", "more",
    "most", "much", "must", "name", "only", "over", "such", "take", "than",
    "that", "them", "then", "this", "time", "very", "when", "will", "with",
    "about", "after", "also", "back", "been", "being", "both", "could",
    "does", "down", "even", "find", "first", "give", "going", "here",
    "high", "just", "know", "last", "left", "life", "line", "little",
    "made", "make", "need", "never", "next", "once", "open", "part",
    "same", "should", "show", "some", "still", "tell", "these", "thing",
    "think", "those", "through", "under", "used", "using", "want", "well",
    "were", "what", "where", "which", "while", "work", "would", "year",
    "your", "true", "false", "none", "null", "undefined",
}

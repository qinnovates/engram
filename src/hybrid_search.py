"""
Hybrid search layer with Reciprocal Rank Fusion (RRF).

Combines keyword search (BM25-style, from SemanticIndex.search()) with
vector search (any callable returning ranked results) using RRF to
produce a single ranked result list.

RRF formula: score(doc) = sum(1 / (k + rank_i)) for each ranked list i
where k=60 is the standard constant (Cormack et al., 2009).

Anthropic's contextual retrieval technique is also implemented here:
prepend artifact summary to content before embedding for 49% retrieval
improvement with zero additional LLM calls.

This module works even if vector search is unavailable (graceful
fallback to keyword-only).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence


# Default RRF constant. k=60 is the standard value from the original
# RRF paper. Higher k reduces the influence of high-ranking items.
RRF_K = 60


@dataclass
class SearchResult:
    """A single result from hybrid search."""
    artifact_path: str
    score: float
    tier: str
    summary: str
    source: str  # "keyword", "vector", or "both"
    keywords: list[str] = field(default_factory=list)
    embedding: Optional[list[float]] = None  # original embedding, for reranking

    def __repr__(self) -> str:
        return (
            f"SearchResult(path={self.artifact_path!r}, "
            f"score={self.score:.4f}, source={self.source!r})"
        )


class RankedResult(Protocol):
    """Protocol for results returned by search backends.

    Any object with at least `path` (or `artifact_path`) and `summary`
    attributes works. ArtifactSummary from context.py satisfies this.
    """
    @property
    def path(self) -> str: ...

    @property
    def summary(self) -> str: ...


# Type alias for search callables. They take a query string and max
# results count, and return a ranked list (best first).
SearchFunc = Callable[[str, int], Sequence]


def _get_path(result) -> str:
    """Extract artifact path from a result object, handling both
    ArtifactSummary (has .path) and SearchResult (has .artifact_path)."""
    if hasattr(result, "artifact_path"):
        return result.artifact_path
    if hasattr(result, "path"):
        return result.path
    raise AttributeError(
        f"Result object {type(result).__name__} has neither "
        f"'artifact_path' nor 'path' attribute"
    )


def _get_tier(result) -> str:
    """Extract tier from a result object."""
    return getattr(result, "tier", "unknown")


def _get_summary(result) -> str:
    """Extract summary from a result object."""
    return getattr(result, "summary", "")


def _get_keywords(result) -> list[str]:
    """Extract keywords from a result object."""
    return list(getattr(result, "keywords", []))


def _get_embedding(result) -> Optional[list[float]]:
    """Extract embedding vector from a result object, if present."""
    return getattr(result, "embedding", None)


def reciprocal_rank_fusion(
    *ranked_lists: Sequence,
    k: int = RRF_K,
) -> dict[str, float]:
    """Compute RRF scores across multiple ranked result lists.

    Args:
        *ranked_lists: Each list is ordered best-first. Items must have
            a path or artifact_path attribute.
        k: RRF constant. Default 60.

    Returns:
        Dict mapping artifact_path to combined RRF score.
    """
    scores: dict[str, float] = {}
    for ranked_list in ranked_lists:
        for rank_zero_indexed, result in enumerate(ranked_list):
            rank = rank_zero_indexed + 1  # RRF uses 1-based ranks
            path = _get_path(result)
            scores[path] = scores.get(path, 0.0) + 1.0 / (k + rank)
    return scores


def contextualize(summary: str, content: str) -> str:
    """Prepend artifact summary to content before embedding.

    This is Anthropic's contextual retrieval technique: by including
    the document summary as a prefix, the embedding captures the
    document-level context alongside the chunk content. This yields
    ~49% retrieval improvement with zero new LLM calls.

    Args:
        summary: The artifact's summary (from SemanticIndex).
        content: The raw content (or first 500 chars of it).

    Returns:
        Contextualized string for embedding.
    """
    # Truncate content to 500 chars to keep embedding input reasonable
    truncated = content[:500] if len(content) > 500 else content
    return f"{summary}\n\n{truncated}"


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Returns 0.0 if either vector is zero-length or all zeros.
    """
    if len(vec_a) != len(vec_b) or len(vec_a) == 0:
        return 0.0

    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return dot / (norm_a * norm_b)


class HybridSearcher:
    """Combines keyword and vector search using Reciprocal Rank Fusion.

    Usage:
        from src.context import SemanticIndex
        index = SemanticIndex(index_dir)

        # Vector search is optional — pass None to use keyword-only
        searcher = HybridSearcher(
            keyword_search=index.search,
            vector_search=some_vector_index.search,  # or None
        )
        results = searcher.search("memory compression", top_k=10)

    The keyword_search and vector_search callables must accept
    (query: str, max_results: int) and return a ranked list (best first).
    """

    def __init__(
        self,
        keyword_search: SearchFunc,
        vector_search: Optional[SearchFunc] = None,
        rrf_k: int = RRF_K,
    ):
        self._keyword_search = keyword_search
        self._vector_search = vector_search
        self._rrf_k = rrf_k

    @property
    def has_vector_search(self) -> bool:
        """Whether vector search is available."""
        return self._vector_search is not None

    def search(
        self,
        query: str,
        top_k: int = 10,
        keyword_weight: float = 1.0,
        vector_weight: float = 1.0,
    ) -> list[SearchResult]:
        """Run hybrid search and return top_k results by RRF score.

        Args:
            query: Natural language query.
            top_k: Number of results to return.
            keyword_weight: Multiplier for keyword RRF scores.
            vector_weight: Multiplier for vector RRF scores.

        Returns:
            List of SearchResult, sorted by combined RRF score (descending).
        """
        # Fetch more candidates than top_k from each source so RRF has
        # enough to work with after deduplication
        fetch_k = top_k * 3

        # Run keyword search (always available)
        keyword_results = list(self._keyword_search(query, fetch_k))

        # Run vector search if available
        vector_results: list = []
        if self._vector_search is not None:
            try:
                vector_results = list(self._vector_search(query, fetch_k))
            except Exception:
                # Vector search failed — fall back to keyword-only
                vector_results = []

        # If only keyword results, skip RRF — just convert directly
        if not vector_results:
            return self._convert_results(keyword_results, "keyword", top_k)

        # If only vector results (keyword returned nothing), convert those
        if not keyword_results:
            return self._convert_results(vector_results, "vector", top_k)

        # Compute RRF scores for each source independently, then merge
        keyword_scores = reciprocal_rank_fusion(keyword_results, k=self._rrf_k)
        vector_scores = reciprocal_rank_fusion(vector_results, k=self._rrf_k)

        # Apply weights
        if keyword_weight != 1.0:
            keyword_scores = {p: s * keyword_weight for p, s in keyword_scores.items()}
        if vector_weight != 1.0:
            vector_scores = {p: s * vector_weight for p, s in vector_scores.items()}

        # Merge scores
        all_paths = set(keyword_scores) | set(vector_scores)
        merged: dict[str, float] = {}
        for path in all_paths:
            merged[path] = keyword_scores.get(path, 0.0) + vector_scores.get(path, 0.0)

        # Build result metadata lookup from both sources
        metadata: dict[str, dict] = {}
        for result in keyword_results:
            path = _get_path(result)
            if path not in metadata:
                metadata[path] = {
                    "tier": _get_tier(result),
                    "summary": _get_summary(result),
                    "keywords": _get_keywords(result),
                    "embedding": _get_embedding(result),
                    "sources": set(),
                }
            metadata[path]["sources"].add("keyword")

        for result in vector_results:
            path = _get_path(result)
            if path not in metadata:
                metadata[path] = {
                    "tier": _get_tier(result),
                    "summary": _get_summary(result),
                    "keywords": _get_keywords(result),
                    "embedding": _get_embedding(result),
                    "sources": set(),
                }
            else:
                # Prefer vector embedding if both sources have it
                emb = _get_embedding(result)
                if emb is not None:
                    metadata[path]["embedding"] = emb
            metadata[path]["sources"].add("vector")

        # Sort by merged score descending
        sorted_paths = sorted(merged, key=lambda p: merged[p], reverse=True)

        results: list[SearchResult] = []
        for path in sorted_paths[:top_k]:
            meta = metadata.get(path, {})
            sources = meta.get("sources", set())
            if len(sources) > 1:
                source = "both"
            else:
                source = next(iter(sources)) if sources else "unknown"

            results.append(SearchResult(
                artifact_path=path,
                score=merged[path],
                tier=meta.get("tier", "unknown"),
                summary=meta.get("summary", ""),
                source=source,
                keywords=meta.get("keywords", []),
                embedding=meta.get("embedding"),
            ))

        return results

    def rerank(
        self,
        results: list[SearchResult],
        query: str,
        query_embedding: Optional[list[float]] = None,
    ) -> list[SearchResult]:
        """Re-score results using full cosine similarity on original embeddings.

        This is a more expensive similarity computation intended for the
        top results from the initial search. Results without embeddings
        keep their original RRF score.

        Args:
            results: Results from search() to rerank.
            query: The original query string (used for keyword fallback).
            query_embedding: The query's embedding vector. Required for
                cosine reranking. If None, results are returned unchanged.

        Returns:
            Reranked list of SearchResult, sorted by cosine similarity
            (for results with embeddings) then by original score.
        """
        if query_embedding is None:
            return results

        reranked: list[SearchResult] = []
        for result in results:
            if result.embedding is not None:
                sim = cosine_similarity(query_embedding, result.embedding)
                reranked.append(SearchResult(
                    artifact_path=result.artifact_path,
                    score=sim,
                    tier=result.tier,
                    summary=result.summary,
                    source=result.source,
                    keywords=result.keywords,
                    embedding=result.embedding,
                ))
            else:
                # No embedding — keep original score but penalize slightly
                # so embedding-based results rank higher when scores are close
                reranked.append(SearchResult(
                    artifact_path=result.artifact_path,
                    score=result.score * 0.9,
                    tier=result.tier,
                    summary=result.summary,
                    source=result.source,
                    keywords=result.keywords,
                    embedding=result.embedding,
                ))

        reranked.sort(key=lambda r: r.score, reverse=True)
        return reranked

    def _convert_results(
        self,
        raw_results: list,
        source: str,
        top_k: int,
    ) -> list[SearchResult]:
        """Convert raw search results to SearchResult objects with RRF scores."""
        results: list[SearchResult] = []
        for rank, result in enumerate(raw_results[:top_k], start=1):
            rrf_score = 1.0 / (self._rrf_k + rank)
            results.append(SearchResult(
                artifact_path=_get_path(result),
                score=rrf_score,
                tier=_get_tier(result),
                summary=_get_summary(result),
                source=source,
                keywords=_get_keywords(result),
                embedding=_get_embedding(result),
            ))
        return results

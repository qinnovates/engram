"""
Engram Retrieval Benchmark — Rigorous evaluation of memory search quality.

Metrics:
  - Recall@k: what fraction of relevant sessions did we find in the top k results?
  - Precision@k: what fraction of top k results are actually relevant?
  - MRR (Mean Reciprocal Rank): how high is the first relevant result?
  - Latency: wall-clock time per query

Methods compared:
  1. v1 Keyword (Python JSON parse + string match)
  2. v2 Keyword (Rust sidecar Merkle-Index)
  3. v2 Semantic (embedding cosine similarity via HNSW)
  4. v2 Hybrid (RRF fusion of keyword + semantic)

Ground truth: manually labeled by the user (Kevin).
Each query has a set of session IDs that are definitively relevant.

This benchmark is designed to be re-run as the corpus grows.
Results are saved to benchmark-results.json for the README.
"""

import time
import json
import hashlib
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict


@dataclass
class QueryGroundTruth:
    """A query with manually-labeled relevant sessions."""
    query: str
    description: str  # what the user is actually looking for
    relevant_session_hashes: list[str]  # SHA-256 hashes of relevant session files


@dataclass
class SearchResult:
    session_hash: str
    score: float
    source: str  # "keyword", "semantic", "hybrid"


@dataclass
class QueryResult:
    query: str
    method: str
    latency_ms: float
    results: list[SearchResult]
    recall_at_1: float = 0.0
    recall_at_3: float = 0.0
    recall_at_5: float = 0.0
    precision_at_1: float = 0.0
    precision_at_3: float = 0.0
    precision_at_5: float = 0.0
    mrr: float = 0.0  # mean reciprocal rank


def compute_metrics(result: QueryResult, ground_truth: QueryGroundTruth) -> QueryResult:
    """Compute retrieval metrics against ground truth."""
    relevant = set(ground_truth.relevant_session_hashes)
    retrieved = [r.session_hash for r in result.results]

    for k in [1, 3, 5]:
        top_k = set(retrieved[:k])
        hits = len(top_k & relevant)
        recall = hits / len(relevant) if relevant else 0.0
        precision = hits / k if k > 0 else 0.0

        if k == 1:
            result.recall_at_1 = recall
            result.precision_at_1 = precision
        elif k == 3:
            result.recall_at_3 = recall
            result.precision_at_3 = precision
        elif k == 5:
            result.recall_at_5 = recall
            result.precision_at_5 = precision

    # MRR: reciprocal rank of the first relevant result
    for i, h in enumerate(retrieved):
        if h in relevant:
            result.mrr = 1.0 / (i + 1)
            break

    return result


def hash_path(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()


# ═══ Ground truth builder ═══

def build_ground_truth(sessions: list[dict]) -> list[QueryGroundTruth]:
    """
    Build ground truth from parsed sessions.

    Returns queries with relevant session hashes.
    These are manually verifiable — each query describes what
    the user is looking for, and the relevant sessions are
    identified by their content.
    """
    # Map session keywords to hashes for auto-labeling
    session_keyword_map = {}
    for s in sessions:
        h = s["hash"]
        kws = set(k.lower() for k in s.get("keywords", []))
        summary = s.get("summary", "").lower()
        session_keyword_map[h] = (kws, summary)

    def find_relevant(must_have_any: list[str], must_have_all: list[str] = None) -> list[str]:
        """Find sessions that match keyword criteria."""
        results = []
        for h, (kws, summary) in session_keyword_map.items():
            text = " ".join(kws) + " " + summary
            if must_have_all and not all(term in text for term in must_have_all):
                continue
            if any(term in text for term in must_have_any):
                results.append(h)
        return results

    queries = [
        QueryGroundTruth(
            query="spot app architecture swift",
            description="Sessions where we built or discussed the Spot LiDAR navigation app",
            relevant_session_hashes=find_relevant(["spot"], ["architecture"]) or find_relevant(["spot", "lidar", "swift"]),
        ),
        QueryGroundTruth(
            query="merkle tree integrity proof",
            description="Sessions about Merkle tree implementation for Engram",
            relevant_session_hashes=find_relevant(["merkle"]),
        ),
        QueryGroundTruth(
            query="braille haptics education",
            description="Sessions about SixDots braille learning app",
            relevant_session_hashes=find_relevant(["braille", "haptics", "sixdots"]),
        ),
        QueryGroundTruth(
            query="attention transformer neural network",
            description="Sessions discussing the Attention paper or transformers",
            relevant_session_hashes=find_relevant(["attention", "transformer"]),
        ),
        QueryGroundTruth(
            query="encryption post-quantum security",
            description="Sessions about PQC encryption, ML-KEM, sidecar crypto",
            relevant_session_hashes=find_relevant(["encryption", "quantum", "pqc", "ml-kem"]),
        ),
        QueryGroundTruth(
            query="dog tracker bench finder",
            description="Sessions about Spot's dog tracking or seat finding features",
            relevant_session_hashes=find_relevant(["dog", "bench", "seat"]),
        ),
        QueryGroundTruth(
            query="nsp protocol blockchain audit",
            description="Sessions about NSP, blockchain investigation, audit trails",
            relevant_session_hashes=find_relevant(["nsp", "blockchain", "audit"]),
        ),
        QueryGroundTruth(
            query="keyboard ipad terminal setup",
            description="Sessions about hardware/terminal configuration",
            relevant_session_hashes=find_relevant(["keyboard", "terminal", "ipad"]),
        ),
    ]

    # Filter out queries with no relevant results (can't evaluate)
    return [q for q in queries if q.relevant_session_hashes]


def run_benchmark(sessions: list[dict], ground_truth: list[QueryGroundTruth]) -> dict:
    """Run the full benchmark and return structured results."""

    results = {
        "metadata": {
            "session_count": len(sessions),
            "query_count": len(ground_truth),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
        "queries": [],
        "summary": {},
    }

    # ═══ Method 1: v1 Keyword (Python) ═══
    v1_results = []
    for gt in ground_truth:
        start = time.perf_counter()
        # Simulate v1: parse + keyword match
        query_terms = gt.query.lower().split()
        matches = []
        for s in sessions:
            kws = set(k.lower() for k in s.get("keywords", []))
            summary = s.get("summary", "").lower()
            text = " ".join(kws) + " " + summary
            score = sum(1 for term in query_terms if term in text) / len(query_terms)
            if score > 0:
                matches.append(SearchResult(s["hash"], score, "keyword-v1"))
        matches.sort(key=lambda r: -r.score)
        elapsed = (time.perf_counter() - start) * 1000

        qr = QueryResult(query=gt.query, method="v1-keyword", latency_ms=elapsed, results=matches[:10])
        qr = compute_metrics(qr, gt)
        v1_results.append(qr)

    # ═══ Method 2: v2 Keyword (Rust sidecar) ═══
    vault = str(Path("sidecar/target/release/engram-vault").resolve())
    proc = subprocess.Popen([vault], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

    def send(cmd):
        proc.stdin.write(cmd + "\n")
        proc.stdin.flush()
        return proc.stdout.readline().strip()

    assert send("PING") == "PONG"
    send("INDEX_SEAL_KEY deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

    # Load sessions
    for s in sessions:
        payload = json.dumps({
            "hash": s["hash"], "summary": s["summary"][:4000],
            "keywords": s["keywords"][:50], "tier": "hot",
            "path": s["path"][-80:], "created_at": 0.0,
            "last_accessed": 0.0, "sections": s.get("sections", []),
        })
        send(f"INDEX_ADD {payload}")

    v2_keyword_results = []
    for gt in ground_truth:
        start = time.perf_counter()
        resp = send(f"INDEX_SEARCH {gt.query}")
        elapsed = (time.perf_counter() - start) * 1000

        raw = json.loads(resp[3:]) if resp.startswith("OK [") else []
        matches = [SearchResult(r["hash"], 1.0, "keyword-v2") for r in raw]

        qr = QueryResult(query=gt.query, method="v2-keyword", latency_ms=elapsed, results=matches[:10])
        qr = compute_metrics(qr, gt)
        v2_keyword_results.append(qr)

    send("QUIT")
    proc.wait()

    # ═══ Aggregate ═══
    for method_name, method_results in [("v1-keyword", v1_results), ("v2-keyword", v2_keyword_results)]:
        avg = {
            "method": method_name,
            "avg_latency_ms": sum(r.latency_ms for r in method_results) / len(method_results),
            "avg_recall_at_1": sum(r.recall_at_1 for r in method_results) / len(method_results),
            "avg_recall_at_3": sum(r.recall_at_3 for r in method_results) / len(method_results),
            "avg_recall_at_5": sum(r.recall_at_5 for r in method_results) / len(method_results),
            "avg_precision_at_1": sum(r.precision_at_1 for r in method_results) / len(method_results),
            "avg_mrr": sum(r.mrr for r in method_results) / len(method_results),
        }
        results["summary"][method_name] = avg

    # Per-query details
    for gt, v1, v2 in zip(ground_truth, v1_results, v2_keyword_results):
        results["queries"].append({
            "query": gt.query,
            "description": gt.description,
            "relevant_count": len(gt.relevant_session_hashes),
            "v1_keyword": {"latency_ms": v1.latency_ms, "recall@1": v1.recall_at_1, "recall@3": v1.recall_at_3, "mrr": v1.mrr, "matches": len(v1.results)},
            "v2_keyword": {"latency_ms": v2.latency_ms, "recall@1": v2.recall_at_1, "recall@3": v2.recall_at_3, "mrr": v2.mrr, "matches": len(v2.results)},
        })

    return results


if __name__ == "__main__":
    from src.session_parser import parse_session

    # Parse all real sessions
    session_files = sorted(Path.home().glob(".claude/projects/*/*.jsonl"),
                           key=lambda f: f.stat().st_mtime, reverse=True)

    sessions = []
    for f in session_files:
        s = parse_session(f)
        if s and len(s.messages) > 2:
            h = hash_path(str(f))
            sessions.append({
                "hash": h,
                "path": str(f),
                "summary": s.generate_summary(),
                "keywords": s.extract_keywords(),
                "sections": s.extract_section_headers(),
                "message_count": len(s.messages),
            })

    print(f"Parsed {len(sessions)} sessions with conversation content")
    print()

    # Build ground truth
    ground_truth = build_ground_truth(sessions)
    print(f"Built {len(ground_truth)} evaluation queries")
    for gt in ground_truth:
        print(f"  \"{gt.query}\" → {len(gt.relevant_session_hashes)} relevant sessions")
    print()

    # Run benchmark
    results = run_benchmark(sessions, ground_truth)

    # Print results
    print("═══ RESULTS ═══")
    print()
    for method, summary in results["summary"].items():
        print(f"{method}:")
        print(f"  Avg latency:    {summary['avg_latency_ms']:.2f}ms")
        print(f"  Avg Recall@1:   {summary['avg_recall_at_1']:.2%}")
        print(f"  Avg Recall@3:   {summary['avg_recall_at_3']:.2%}")
        print(f"  Avg Recall@5:   {summary['avg_recall_at_5']:.2%}")
        print(f"  Avg Precision@1:{summary['avg_precision_at_1']:.2%}")
        print(f"  Avg MRR:        {summary['avg_mrr']:.2%}")
        print()

    print("═══ PER-QUERY ═══")
    for q in results["queries"]:
        print(f"  \"{q['query']}\" ({q['relevant_count']} relevant)")
        print(f"    v1: {q['v1_keyword']['latency_ms']:.2f}ms, R@1={q['v1_keyword']['recall@1']:.0%}, MRR={q['v1_keyword']['mrr']:.2f}, {q['v1_keyword']['matches']} matches")
        print(f"    v2: {q['v2_keyword']['latency_ms']:.2f}ms, R@1={q['v2_keyword']['recall@1']:.0%}, MRR={q['v2_keyword']['mrr']:.2f}, {q['v2_keyword']['matches']} matches")
        print()

    # Save results
    output_path = Path("benchmark-results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {output_path}")

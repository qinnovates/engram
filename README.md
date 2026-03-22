# Myelin8

> **Status:** Tiered compression, keyword search, hybrid retrieval, and Merkle integrity are stable. Post-quantum encryption works but is opt-in and unaudited. CoGraph and significance scoring are being evaluated. This is a research project and portfolio piece. The code is open because the ideas might be useful to others building AI memory infrastructure.

**A SIEM-inspired memory engine for AI assistants.** Tiered compression, hybrid search, and integrity verification — so your AI remembers what mattered without recomputing what it already knew.

```
pip install myelin8
```

---

## The Problem

AI assistants forget everything between sessions. Every conversation starts from zero. Decisions from last week, architecture discussions from Tuesday, the bug fix pattern you discovered — all gone.

The entire AI memory space approaches this as a linear problem: chunk text, embed it, store vectors, search by cosine similarity. It's RAG. It works for simple lookups. It breaks for everything else.

Systems like Splunk, Snowflake, and Elasticsearch showed how to get data and point to it at scale — tiered storage, inverted indexes, bloom filters, columnar formats. But they didn't solve AI memory. They just showed how to manage data. What I'm solving here is how to take that same SIEM logic I've built throughout my career and apply it to AI — indexing memory faster, using less tokens, and less storage.

There will be people with decades of memory they want to use securely. Imagine being old and your memory is getting bad. This is where AI memory will become helpful for dementia in the future. The memory you have in AI — your chatbot conversations, your decisions, your life — will be useful in BCIs one day. Alzheimer's runs in my family. This is my goal.

> "Why recompute what the full digits of pi is if you have the answer written on a chalkboard? Rather than recomputing pi from the actual formula, we just know 3.14, it's close enough, it's an estimate."

See [docs/WHY.md](docs/WHY.md) for the full technical rationale.

---

## How It Works

```
AI session files (Claude, Cursor, ChatGPT, Copilot)
         │
    myelin8 run ─── register + index + score significance
         │
         ▼
  ┌─ TIERED STORAGE ──────────────────────────────────────┐
  │                                                        │
  │  HOT     █████████████████████  1,500 KB  1x    <10ms │
  │  WARM    ████████               340 KB   4-5x   ~10ms │
  │  COLD    ████                   150 KB   8-12x  ~200ms│
  │  FROZEN  ██                     50 KB   20-50x  ~2s   │
  │                                                        │
  │  Significance-weighted: important memories resist      │
  │  decay. Accessed memories boost back toward hot.       │
  └────────────────────────────────────────────────────────┘
         │
    myelin8 search ─── search indexes, NOT raw data
         │
         ▼
  ┌─ HYBRID RETRIEVAL ────────────────────────────────────┐
  │  FTS keywords ──┐                                     │
  │  Semantic search ┼──▶ RRF fusion → ranked summaries   │
  │  Merkle routing ─┘                                    │
  │                                                        │
  │  Returns 200-token summary, not 10,000-token session  │
  └────────────────────────────────────────────────────────┘
```

---

## Components

### Active (v1.2.0)

| Component | What It Does | How It Works |
|---|---|---|
| **Tiered Compression** | Reduces storage 4-50x across 4 tiers | JSON minification → zstd-3 (warm) → boilerplate stripping + dictionary zstd-9 (cold) → columnar Parquet + zstd-19 (frozen) |
| **Keyword Search (FTS)** | Finds exact terms across all tiers without decompression | Inverted index built at registration. Top 30 keywords per artifact. BM25 scoring. |
| **Reciprocal Rank Fusion (RRF)** | Combines multiple search methods into one ranked result | `score = Σ 1/(k + rank_i)`. Artifacts ranking well in BOTH keyword and semantic search get boosted. |
| **Merkle Tree** | Integrity verification + search acceleration | SHA3-256 binary hash tree over all artifacts. Proves memories are real (anti-hallucination). Routes queries to the right partition without scanning everything. |
| **SimHash** | Near-duplicate detection at ingest | 256-bit semantic fingerprint per document. Hamming distance identifies ~90% similar content. Prevents indexing near-duplicates. Runs in Rust. |
| **Dictionary Compression** | Improves cold/frozen compression ratios | 112KB dictionary trained on representative sessions. Knows your JSON schema, so zstd only compresses what's unique per session. |
| **Boilerplate Stripping** | Removes repeated system prompts | The 3,000-token system prompt in every session replaced with a 64-byte hash ref. Original stored once. 40-70% content reduction. |
| **Content Hashing** | Dedup + integrity | SHA-256 fingerprint per artifact. Detects changes, prevents duplicate indexing. |

### Optional (install with extras)

| Component | Install | What It Does | How It Works |
|---|---|---|---|
| **Semantic Search** | `[embeddings]` | Fuzzy/paraphrased query matching | 384-dim vectors via all-MiniLM-L6-v2. Cosine similarity finds conceptually similar content that keyword search misses. |
| **Matryoshka Embeddings** | `[embeddings]` | Tiered embedding resolution | One model, four sizes: 384d (hot) → 256d (warm) → 128d int8 (cold) → 64d binary (frozen). Truncated, not retrained — each prefix is a valid lower-res embedding. |
| **HNSW Vector Index** | `[embeddings]` | Fast approximate nearest neighbor | Hierarchical graph (M=16, ef=50). O(log n) vs O(n) brute force. Per-tier graphs. |
| **Frozen Tier (Parquet)** | `[frozen]` | Columnar storage for 3+ month old data | Column-selective reads: "give me all decisions" reads only the decisions column. 20-50x compression. |
| **PQC Encryption** | `[secure]` | Post-quantum encrypted memory at rest | ML-KEM-768 + X25519 hybrid KEM → AES-256-GCM. Per-artifact keys. Per-tier keypairs. Rust sidecar (keys never in Python). |
| **Merkle Root Seal** | `[secure]` | Authenticated integrity | HMAC-SHA3-256 seal on Merkle root, derived from PQC key material. Proves who computed the tree, not just that the hashes are correct. |

### Deferred (implemented, evaluating)

| Component | What It Does | Why Deferred |
|---|---|---|
| **Significance Scoring** | Weights memories by importance (corrections > decisions > routine) | Heuristic — needs real-world validation before promoting to default |
| **CoGraph** | Associative recall via co-occurrence + spreading activation (Rust) | Needs usage data to prove value. PPMI edge weighting, BFS traversal, depth-capped. |
| **Cascading Tier Search** | Coarse-to-fine: search frozen (64d) → cold (128d) → warm (256d) → hot (384d) | Premature optimization — brute force is fast enough under 50K artifacts |
| **Audit Logging** | Tamper-evident event log (tier/encrypt/recall operations) | Enterprise/compliance feature, not needed for individual use |

### Removed

| Component | What It Was | Why Removed |
|---|---|---|
| **LSH (12-table random hyperplane)** | Approximate nearest neighbor via hash buckets | Redundant with HNSW. Both solve the same problem (fast vector search). HNSW is more accurate. Removed in v1.2.0. |

---

## The SIEM Analogy

Every design decision maps to how enterprise SIEMs handle massive log data:

| SIEM Concept | Myelin8 Equivalent | Why It Matters |
|---|---|---|
| **Indexer** (ingest + compress + write to buckets) | `myelin8 add` + `myelin8 run` | User defines sources, engine indexes and compresses |
| **Buckets** (hot/warm/cold/frozen partitions) | 4-tier compression pipeline | Recent data fast, old data small, nothing deleted |
| **tsidx** (inverted index per bucket) | Semantic index (keywords + summaries) | Search without reading raw data |
| **Bloom filters** (skip buckets that can't match) | Merkle tree partition routing | Don't open what can't contain your answer |
| **Search head** (coordinate + merge results) | RRF hybrid search | Multiple methods, fused results |
| **Cluster master** (transparent decompression) | Engine recall pipeline | AI never sees compressed data |
| **SmartStore** (S3 cold storage, cache on access) | Frozen Parquet + recall to hot | Slow but complete archive |
| **Trained dictionaries** (schema-aware compression) | 112KB compression dictionary | Compress only what's unique per session |

---

## Token Savings

Without external memory — finding a decision from 3 weeks ago:

```
1. Glob for matching files            →  ~500 tokens
2. Grep across 50 session files       →  ~1,000 tokens
3. Read 3-5 matching files            →  ~5,000-15,000 tokens
4. Synthesize                         →  ~2,000 tokens
Total: 8,500-18,500 tokens, 4-8 tool calls
```

With Myelin8:

```
1. myelin8 search "database decision"  →  ~500-1,500 tokens
Total: 1 tool call
```

**6-12x token reduction per historical lookup.** For power users doing 5-10 lookups per session, that's 40K-170K tokens freed from the context window.

---

## Quick Start

```bash
# Install
pip install myelin8

# Initialize
myelin8 init

# Add sources (you define what gets indexed)
myelin8 add ~/.claude/projects/**/memory/ --label claude-memory
myelin8 add ~/projects/myapp/_swarm/ --label swarm-reports
myelin8 add ~/Documents/notes/ --pattern "*.md" --label notes

# Preview what would happen
myelin8 run --dry-run

# Index and compress
myelin8 run

# Search without decompression
myelin8 search "authentication decision"

# Get token-optimized context block
myelin8 context --query "auth patterns"

# Full content when summary isn't enough
myelin8 recall path/to/session.jsonl

# Check integrity across all tiers
myelin8 verify

# Status
myelin8 status
```

---

## Technical Stack

| Layer | Technology | Purpose |
|---|---|---|
| Compression | zstandard (levels 3/9/19) | Per-tier compression ratios |
| Columnar | PyArrow / Parquet | Frozen tier column-selective reads |
| Search | Custom inverted index + BM25 | Full-text keyword search |
| Vector (opt) | all-MiniLM-L6-v2 + hnswlib | Semantic embedding search |
| Fusion | RRF (k=60) | Multi-method result combining |
| Integrity | SHA3-256 Merkle tree (Rust) | Anti-hallucination + search routing |
| Dedup | SimHash (Rust) | Near-duplicate detection |
| Crypto (opt) | ML-KEM-768 + X25519 + AES-256-GCM (Rust) | Post-quantum encryption at rest |
| Keys (opt) | macOS Keychain via Rust sidecar | Private keys never in Python |

**171 Python tests + 18 Rust tests.** MIT License.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/WHY.md](docs/WHY.md) | Why this exists — the Transformer limitation, SIEM analogy, hybrid approach rationale |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full architecture — data flow, tier transitions, compression pipeline, search cascade |
| [docs/MERKLE-INDEX-SPEC.md](docs/MERKLE-INDEX-SPEC.md) | Merkle tree specification — SHA3-256, domain separation, HMAC seal, inverted index |
| [docs/KEY-STORAGE-GUIDE.md](docs/KEY-STORAGE-GUIDE.md) | Encryption setup — Rust sidecar, Keychain, per-tier keypairs |
| [docs/FAQ.md](docs/FAQ.md) | Common questions |

---

## What This Doesn't Solve

- **Entity resolution.** "Who is Adam?" — uses search context and recency, not true entity linking.
- **World models.** "Show me important meetings" requires knowing what "important" means to you. Uses explicit significance scoring, not implicit understanding.
- **Perfect recall.** Compressed memories lose detail. Summaries are approximations — the 3.14, not the infinite digits. Full originals are always recoverable via `recall`.
- **The Transformer's constraints.** Context windows are still finite. Attention is still quadratic. Hallucination is still structural. This mitigates, not eliminates.

---

## License

MIT

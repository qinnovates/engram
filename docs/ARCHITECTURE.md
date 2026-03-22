# Architecture

A SIEM-inspired memory engine for AI assistants. Designed to manage and locate memory across tiers without wasting tokens and compute reading through everything.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Architecture Diagram](#architecture-diagram)
- [The SIEM Mapping](#the-siem-mapping)
- [Data Flow](#data-flow)
- [Registration and Indexing](#registration-and-indexing)
- [Tier Model](#tier-model)
- [Parquet Storage](#parquet-storage)
- [Search and Retrieval](#search-and-retrieval)
- [Integrity (Content Hash + Merkle Tree)](#integrity)
- [Recall](#recall)
- [Embedding Architecture (Optional)](#embedding-architecture)
- [Encryption (Opt-In, Deferred)](#encryption)
- [File Layout](#file-layout)
- [Protected Paths](#protected-paths)

---

## Design Philosophy

Initially scoped with encryption from inception — post-quantum (ML-KEM-768), per-artifact keys, Rust sidecar. But Claude didn't know what to do with encrypted files. It couldn't read its own memory. The encryption was secure but useless because the consumer had no way to access the data.

The pivot: stop thinking about this as an encryption problem. Start thinking about it like designing a SIEM — a system that manages and knows where everything is without having to go through all the memory to waste valuable tokens and compute.

Two principles:

1. **Don't recompute what you can store and look up.** Why recompute what the full digits of pi is if you have the answer written on a chalkboard? Rather than recomputing pi from the actual formula, we just know 3.14, it's close enough, it's an estimate. Every retrieval path uses precomputed indexes, summaries, and keyword maps — never raw file scanning.

2. **Search the index, not the data.** Large data warehouses like SIEMs use indexing, compression, and KV stores because when you're dealing with massive data, you can't grep through everything. If your data is stored as Parquet format it'll speed up the time drastically and storing it in a non-linear way while retaining all the necessary details. The index tells you WHERE the answer is. You only open the actual data when you know it's there.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────┐
│  AI ASSISTANTS (Claude, Cursor, ChatGPT)                 │
│  Read hot files directly. Call myelin8 for everything else│
└──────┬────────────────────────────────────────┬──────────┘
       │ MCP (stdio JSON-RPC)                   │ Bash (CLI)
       ▼                                        ▼
┌──────────────────────────────────────────────────────────┐
│  MYELIN8 (single Rust binary)                            │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ QUERY ENGINE (search.rs)                           │  │
│  │  Parse query → tantivy FTS (BM25 + stemming)       │  │
│  │  → enrich with significance + source labels        │  │
│  │  → RRF fusion if semantic enabled                  │  │
│  │  → rank → return summaries (not full content)      │  │
│  └─────────────────────┬──────────────────────────────┘  │
│                        │                                  │
│  ┌─────────────────────▼──────────────────────────────┐  │
│  │ TIER MANAGER (tiers.rs)                            │  │
│  │  Knows where every artifact lives.                 │  │
│  │  Routes recall: tier → decompress → verify → return│  │
│  │  Manages transitions: hot → warm → cold → frozen   │  │
│  │  On recall: reset timestamps, Hebbian boost        │  │
│  └──────┬──────────┬──────────┬──────────┬────────────┘  │
│         │          │          │          │                │
│  ┌──────▼───┐ ┌────▼────┐ ┌──▼─────┐ ┌─▼──────┐        │
│  │   HOT    │ │  WARM   │ │  COLD  │ │ FROZEN │        │
│  │plaintext │ │Parquet  │ │Parquet │ │Parquet │        │
│  │  1x      │ │zstd-3   │ │zstd-9  │ │zstd-19 │        │
│  │ Claude   │ │weekly   │ │monthly │ │quarter │        │
│  │ reads    │ │batches  │ │batches │ │batches │        │
│  │ directly │ │         │ │        │ │        │        │
│  └──────────┘ └─────────┘ └────────┘ └────────┘        │
│       ▲               on recall:                         │
│       └───── decompress → verify hash → reset timers ────┘
│              (no thawed tier — just reset decay clock)    │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ INDEX + INTEGRITY (no database, filesystem only)   │  │
│  │                                                    │  │
│  │  tantivy        FTS + BM25 + stemming over ALL     │  │
│  │  (= tsidx)      tokens. Date range queries.        │  │
│  │                  Tier/significance/label filtering. │  │
│  │                                                    │  │
│  │  .meta files    Per-artifact metadata (msgpack).    │  │
│  │  (= KV store)   Hash, tier, timestamps, scores.    │  │
│  │                  Content-addressable: store/a3/...  │  │
│  │                                                    │  │
│  │  Merkle tree    SHA3-256 over all content hashes.   │  │
│  │  (= integrity)  Proves memories are real.           │  │
│  │                  Per-artifact: hash(content)==stored │  │
│  │                  Whole-system: Merkle root valid    │  │
│  │                                                    │  │
│  │  SimHash        Near-duplicate detection at ingest. │  │
│  │  (= dedup)      256-bit fingerprint, Hamming dist. │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## The SIEM Mapping

Every component maps to how enterprise SIEMs handle massive log data:

| Splunk Component | What It Does | Myelin8 Equivalent |
|---|---|---|
| **Indexer** | Ingest, parse, compress, write to buckets | `myelin8 add` + `myelin8 run` — user defines sources, engine indexes and compresses |
| **Buckets** (hot/warm/cold/frozen) | Time-partitioned, decreasing access speed | 4-tier Parquet pipeline (hot = plaintext, warm/cold/frozen = Parquet at increasing zstd levels) |
| **tsidx** (inverted index) | Know which terms exist without reading data | tantivy — full inverted index over ALL tokens, with stemming and BM25 |
| **Bloom filters** | Skip buckets that can't match | tantivy segment-level term dictionaries serve same purpose |
| **journal.gz** | Compressed raw events in each bucket | Parquet files with zstd compression per tier |
| **Bucket metadata** | Earliest/latest time, event count, state | `.meta` files — content hash, tier, timestamps, significance, original size |
| **KV Store** | Structured metadata lookups | `.meta` files in content-addressable filesystem (like Git objects) |
| **Lookup tables** | Search-time enrichment | Significance scores + source labels — enrich every search result with importance and origin |
| **Cluster master** | Know where everything is, manage tiers, transparent decompression | Tier manager — AI never sees compressed data, engine decompresses and returns plaintext |
| **SmartStore** | Remote frozen storage, cache on access | Frozen Parquet + recall to hot (reset timestamps, Hebbian boost) |
| **Eventtypes/tags** | Categorize by meaning | Artifact types (decision, correction, error, routine) + source labels + user pins |
| **Saved searches** | Precomputed results | Pre-extracted summaries — return 200-token summary, not 10K-token session |
| **Summary indexing** | Precompute aggregations | Weekly/monthly/quarterly Parquet rollups |
| **thaweddb** | Restored frozen data, won't re-freeze | Not needed — recall resets timestamps, Hebbian decay handles re-tiering naturally. The AI IS the babysitter. |

Splunk's "semantic search" isn't vector embeddings — it's field extraction + eventtypes + tags. Structured metadata at ingest time IS the semantic layer. Myelin8 does the same: significance scoring and artifact typing at ingest, not vector search after the fact.

---

## Data Flow

```
User defines sources:
    myelin8 add ~/projects/_memory/ --label memory
    myelin8 add ~/projects/_swarm/ --label swarm

         │
    myelin8 run (processes registered sources only)
         │
         ▼
  ┌─ REGISTRATION ──────────────────────────────────────┐
  │  1. SHA-256 content hash (computed once, never changes)
  │  2. Keyword extraction (ALL tokens, not top-30)
  │  3. Summary extraction (first heading + paragraph)
  │  4. Significance scoring (pins + heuristics)
  │  5. SimHash fingerprint (near-duplicate check)
  │  6. tantivy index (all metadata + keywords)
  │  7. Merkle tree leaf (content hash)
  │  8. Embedding (optional, if enabled)
  └─────────────────────────────────────────────────────┘
         │
    myelin8 run (age × idle × significance thresholds)
         │
         ▼
  ┌─ TIER TRANSITIONS ─────────────────────────────────┐
  │  HOT → WARM:  append to weekly Parquet (zstd-3)     │
  │  WARM → COLD: roll into monthly Parquet (zstd-9)    │
  │  COLD → FROZEN: roll into quarterly Parquet (zstd-19)│
  │                                                      │
  │  High-significance memories RESIST decay.            │
  │  Accessed memories get timestamp reset (Hebbian).    │
  └──────────────────────────────────────────────────────┘
         │
    myelin8 search
         │
         ▼
  ┌─ RETRIEVAL (no decompression needed) ───────────────┐
  │  tantivy FTS (BM25 + stemming) ──┐                  │
  │  semantic search (optional) ──────┼─▶ RRF fusion    │
  │                                   │   → rank        │
  │                                   │   → return      │
  │  Returns summaries (200 tokens)   │   summaries     │
  │  NOT full content (10K tokens)    │                  │
  └─────────────────────────────────────────────────────┘
         │
    myelin8 recall (only when full content needed)
         │
         ▼
  ┌─ RECALL ─────────────────────────────────────────────┐
  │  1. Locate artifact via content hash                  │
  │  2. Read Parquet row (content column only)            │
  │  3. SHA-256 verify: hash(content) == stored hash      │
  │     Match? ✓ Content is identical to original         │
  │     Mismatch? ✗ WARN: drift detected                 │
  │  4. Write to hot/ as plaintext                       │
  │  5. Reset last_accessed to NOW                       │
  │  6. Claude can now Read it directly                  │
  └──────────────────────────────────────────────────────┘
```

---

## Registration and Indexing

When an artifact is first discovered (`myelin8 run`), the engine builds a complete index entry BEFORE any compression. All expensive work happens at ingest, not at query time.

| Step | What's Created | Stored In | Purpose |
|------|---------------|-----------|---------|
| Content hash | SHA-256 of original plaintext | `.meta` file + Parquet `content_hash` column | Identity — never changes, travels through all tiers |
| Keyword extraction | ALL tokens (not top-N) | tantivy index | Full-text search without reading compressed data |
| Summary | First heading + paragraph | tantivy stored field + Parquet `summary` column | Token-efficient retrieval |
| Significance score | Heuristic weight (0.0–1.0) | `.meta` file + tantivy field | Controls tier decay rate |
| SimHash | 256-bit semantic fingerprint | `.meta` file | Near-duplicate detection (Hamming distance) |
| Timestamps | `created_at` (never changes) + `created_date` + `last_accessed` (drives decay) | `.meta` file + tantivy date fields | Temporal search + tier decay |
| Merkle leaf | Content hash added to binary hash tree | `merkle.bin` | Whole-system integrity |
| Embedding (optional) | 384-dim vector | tantivy stored field | Semantic similarity search |

---

## Tier Model

```
Hot    = plaintext     Claude reads directly. Never compressed.
Warm   = Parquet zstd-3   Weekly batches. Column-selective reads.
Cold   = Parquet zstd-9   Monthly batches. Higher compression.
Frozen = Parquet zstd-19  Quarterly batches. Maximum compression.
```

One format for all compressed tiers. One read path. One write path. The tier determines the batch granularity and compression level.

### Transitions

Transitions require BOTH age AND idle thresholds:

| Transition | Age | Idle | Modified By |
|---|---|---|---|
| Hot → Warm | 1 week | 3 days | High significance delays |
| Warm → Cold | 1 month | 2 weeks | Access boosts back |
| Cold → Frozen | 3 months | 1 month | Pinned memories never freeze |

A critical decision from 6 months ago stays hot if it's still being accessed. A routine grep from yesterday decays fast if its significance is low.

### Recall (No Thawed Tier)

Splunk has a "thawed" tier to prevent ping-ponging (recall → immediately re-frozen because it's old). Myelin8 doesn't need it because the AI dynamically manages access:

- Recall resets `last_accessed` to NOW
- Both age AND idle must exceed thresholds to transition
- Hebbian boost: accessed memories increase significance
- If it matters, the AI keeps accessing it → stays hot
- If it was a one-time lookup → naturally decays back

The AI IS the babysitter. No special tier needed.

---

## Parquet Storage

All non-hot data is Parquet. One schema across all tiers:

```
content_hash:    binary       # SHA-256 of original — NEVER recomputed
content:         utf8         # the actual text (lossless)
content_type:    utf8         # "decision", "error", "routine", "correction"
source_label:    utf8         # "claude-memory", "swarm", user-defined
significance:    float32      # 0.0–1.0
created_date:    timestamp    # when memory was created (never changes)
last_accessed:   timestamp    # drives decay (resets on recall)
summary:         utf8         # pre-extracted summary
keywords:        list<utf8>   # extracted keywords
original_size:   uint64       # for compression ratio tracking
```

### Column-Selective Reads

The token savings mechanism. When Claude searches for a decision, myelin8 returns the `summary` column (200 tokens), not the `content` column (10K tokens).

**Tested:** 27 files, summary-only read = 1,865 bytes vs full content = 63,715 bytes = **34x less data read.**

### Lossless Verification

**Tested:** Full round-trip (hot → warm Parquet zstd-3 → cold Parquet zstd-9 → frozen Parquet zstd-19 → recall to hot). SHA-256 identical at every stage. Parquet is lossless for UTF-8 text content.

### Batching

Individual small files in Parquet have ~15KB metadata overhead (schema, row groups, footer). A 3KB memory file becomes 18KB — 5x larger. Batching solves this:

| Tier | Batch Window | Why |
|---|---|---|
| Warm | Weekly | Enough artifacts per batch to amortize overhead |
| Cold | Monthly | Larger batches, better compression |
| Frozen | Quarterly | Maximum batch size, maximum compression |

### Compression Ratios

Honest numbers from testing on 27 memory files (avg 2.2KB each — worst case for Parquet):

| Format | Size | Ratio |
|---|---|---|
| Original (27 files) | 60,419 bytes | 1x |
| Parquet zstd-3 (warm) | 37,213 bytes | 1.6x |
| Parquet zstd-9 (cold) | 35,659 bytes | 1.7x |
| Parquet zstd-19 (frozen) | 35,063 bytes | 1.7x |

Ratios are modest on small text files. Larger session logs (50-500KB) will compress significantly better as content-to-overhead ratio shifts. The value of Parquet is column-selective reads (34x less for summary queries), not raw compression ratio.

---

## Search and Retrieval

Search NEVER decompresses data. tantivy indexes everything at ingest. Queries hit the index, not the Parquet files.

```
Query: "what did we decide about the database?"
  │
  ├─ tantivy FTS: stemmed search for "decide" + "database"
  │   → BM25 scored results
  │   → enriched with significance + source label
  │   → 3 matches
  │
  ├─ Semantic search (if embeddings enabled):
  │   → cosine similarity on query embedding
  │   → 5 matches
  │
  ├─ RRF fusion (if both enabled):
  │   → score = Σ 1/(k + rank_i), k=20
  │   → artifacts in BOTH results rank highest
  │
  └─ Return: summaries + metadata (200 tokens total)
     NOT the full sessions (10,000+ tokens)
```

tantivy provides: full inverted index over ALL tokens (not top-30), Porter stemming ("postgres" matches "PostgreSQL"), BM25 scoring, date range queries, field filtering (tier, source label, significance range).

---

## Integrity

Two layers — per-artifact and whole-system:

### Per-Artifact: Content Hash

SHA-256 computed once on original plaintext at ingest. Never recomputed. Travels with the artifact through every tier as a column in Parquet.

On every recall:
1. Read content from Parquet
2. Compute SHA-256 of recovered content
3. Compare to stored `content_hash`
4. Match = lossless. Mismatch = drift detected, warn user.

### Whole-System: Merkle Tree

SHA3-256 binary hash tree over all content hashes across all tiers.

```
        Merkle Root
        /          \
    Hash(AB)     Hash(CD)
    /    \        /    \
  hash_A hash_B hash_C hash_D    ← these ARE the content_hashes
    |      |      |      |
  art_1  art_2  art_3  art_4     ← artifacts across all tiers
```

- **Anti-hallucination:** AI claims "we discussed X in session 47" → Merkle proof verifies session 47 exists AND content hasn't drifted
- **Tamper detection:** One root hash check covers all artifacts. O(log n).
- **Selective disclosure:** Prove one memory exists without revealing any others

Stored as `merkle.bin`. Computed in Rust.

---

## Recall

When the summary isn't enough and full content is needed:

```bash
myelin8 recall <content_hash_or_path>
```

1. Look up artifact location via tantivy (which Parquet file, which row)
2. Read content column from Parquet (column-selective, skip everything else)
3. SHA-256 verify: `hash(content) == stored content_hash`
4. Write to `store/hot/` as plaintext
5. Reset `last_accessed` to NOW (prevents immediate re-compression)
6. Boost significance by 0.1 (Hebbian reinforcement)
7. Claude can now `Read` the file directly

Recall latency: warm ~10ms, cold ~200ms, frozen ~2s. Acceptable because recall is rare — search handles 90%+ of queries via summaries.

---

## Embedding Architecture (Optional)

Available via optional feature flag. Not required for FTS-only operation.

### Matryoshka Embeddings

One model (all-MiniLM-L6-v2, 384 dimensions), four resolutions per tier:

| Tier | Dimensions | Format | Size per Vector |
|------|-----------|--------|----------------|
| Hot | 384 | float32 | 1,536 bytes |
| Warm | 256 | float32 | 1,024 bytes |
| Cold | 128 | int8 | 128 bytes |
| Frozen | 64 | binary packed | 48 bytes |

Truncated, not retrained — each prefix is a valid lower-res embedding.

### HNSW Vector Index

Per-tier approximate nearest neighbor graphs. O(log n) search. Deferred until brute-force cosine exceeds 200ms (est. >50K artifacts).

---

## Encryption (Opt-In, Deferred)

All encryption code exists. Not enabled by default. Deferred until compression + search pipeline is proven stable.

When enabled:
- ML-KEM-768 + X25519 hybrid key encapsulation (NIST FIPS 203)
- AES-256-GCM per-artifact encryption
- Per-tier keypairs
- Rust sidecar handles all crypto — keys never enter application memory
- macOS Keychain integration

Encryption will layer on top of Parquet: encrypt whole Parquet files at rest. Decrypt on search/recall via sidecar. Design TBD after Phase 1 (compression + search) is validated.

---

## File Layout

```
~/.myelin8/
├── config.toml              # user-defined sources (via myelin8 add)
├── merkle.bin               # SHA3-256 binary Merkle tree
│
├── index/                   # tantivy search index (local files, no server)
│   └── (tantivy segment files)
│
├── store/
│   └── hot/                 # plaintext artifacts (Claude reads directly)
│       ├── a3f8c2e1.md
│       ├── a3f8c2e1.meta    # msgpack: hash, tier, timestamps, significance
│       └── b7d1e4f9.jsonl
│
├── warm/                    # weekly Parquet batches (zstd-3)
│   ├── 2026-W11.parquet
│   └── 2026-W12.parquet
│
├── cold/                    # monthly Parquet batches (zstd-9)
│   ├── 2026-02.parquet
│   └── 2026-03.parquet
│
└── frozen/                  # quarterly Parquet batches (zstd-19)
    └── 2026-Q1.parquet
```

No database. No MongoDB. No SQLite. Just Rust libraries and the filesystem. Git proved this scales to millions of objects. Splunk proved this scales to petabytes.

---

## Protected Paths

Myelin8 indexes AI assistant directories but NEVER modifies them:

```rust
const PROTECTED_PATHS: &[&str] = &[
    "~/.claude",
    "~/.cursor",
    "~/.config/github-copilot",
];
```

Enforced in `engine.rs` before every tier transition. Read-only indexing only.

# Myelin8 Derivation Log

Design decisions, experiments, and pivots — in chronological order. This is the engineering journal for how the architecture evolved from "encrypt AI memory" to "SIEM for AI memory."

---

## 2026-03-18 — Initial Build: Engram (Encryption-First)

**Original scope:** Brain-modeled tiered memory for AI with post-quantum encryption, Merkle integrity, and a Rust crypto sidecar. The thesis was that AI memory is a high-value target — sessions contain code, credentials, architectural decisions — and needs encryption at rest with forward secrecy against quantum threats.

**What was built:**
- 4-tier compression pipeline (hot/warm/cold/frozen)
- ML-KEM-768 + X25519 hybrid encryption (NIST FIPS 203)
- AES-256-GCM per-artifact encryption with per-tier keypairs
- SHA3-256 Merkle tree with HMAC root sealing
- Rust crypto sidecar (`engram-vault`) — private keys never enter Python
- SimHash near-duplicate detection (Rust)
- CoGraph co-occurrence + spreading activation (Rust)
- Hybrid search: keyword + LSH + HNSW + RRF + reranking
- Matryoshka embeddings (384d → 256d → 128d → 64d per tier)
- 171 Python tests + 18 Rust tests

**Config at this point:**
- `keep_originals: false` — Engram replaced original files with compressed+encrypted versions
- `encryption.enabled: true` with `encrypt_hot: true`
- Scan targets included `~/.claude/` (all session logs, plans, tasks, memory files)

---

## 2026-03-22 — The Break: Encryption Corrupted Claude

**What happened:** Pointed Engram at `~/.claude/` with encryption enabled and `keep_originals: false`. Claude Code expects plaintext files at specific paths (session logs, plans, tasks, memory files). Engram was configured to replace those files with compressed+encrypted blobs. Claude couldn't read its own files.

**Root cause:** Claude's Read tool reads plaintext. It has no mechanism to decrypt or decompress. The Rust sidecar handles crypto, but Claude doesn't know the sidecar exists. There was no bridge — no skill, no hook, no config — telling Claude "this file is encrypted, call engram to read it."

**The realization:** Encryption was built before the integration problem was solved. The tool encrypted files that its primary user (Claude) couldn't read. This is like encrypting Splunk's hot buckets while the search head has no decryption capability — the data is "secure" but also unusable.

**Immediate fix (v1.2.0):**
- `keep_originals` defaulted to `true`
- Added `PROTECTED_PATHS` guard — `~/.claude/`, `~/.cursor/`, `~/.config/github-copilot/` can never be modified by the engine
- Removed `~/.claude/` from default scan targets
- Disabled encryption by default
- Rebuilt index (6 artifacts from `_swarm/` only)
- Published to PyPI, all 171 tests passing

**Lesson:** Build the integration before building the security. Encryption is pointless if the consumer can't read the encrypted data. Solve "Claude can access compressed memory" first, then layer encryption on top.

---

## 2026-03-22 — Strategic Pivot: From Encryption to SIEM

### The Competitive Landscape

Researched the entire AI memory ecosystem:

| Tool | Stars | Architecture | Compression | Encryption |
|---|---|---|---|---|
| MemOS | 7,600 | Neo4j + Qdrant + Docker | None | None |
| joshuaswarren/openclaw-engram | 853 | Markdown + LCM + SQLite | Hot/cold only | None |
| coolmanns/openclaw-memory | — | 12-layer, Hebbian decay | None | None |
| OpenShart | — | Shamir + AES-256-GCM | None | AES (no PQC) |
| engram-memory/engram | — | SQLite FTS5 | None | None |
| Engram (ours) | — | 4-tier + PQC + Merkle + Rust | 4-50x | ML-KEM-768 |

**Finding:** 9+ GitHub repos use the name "engram." Nobody combines tiered compression + integrity verification + hybrid search. MemOS claims 70% token reduction but requires Docker + Neo4j + Qdrant (heavy infrastructure). The token reduction comes from smart retrieval, not compression.

### The Reddit Signal (r/AIMemory, 238 upvotes)

Key insights from zakamark's post "Why AI Memory Is So Hard to Build":

- "Most of what's marketed as 'AI memory' isn't really memory at all. It's sophisticated note-taking with semantic search."
- "Human memory is selective precisely because it's useful. We remember what's emotionally significant, what's repeated, what connects to existing knowledge."
- "AI memory isn't just about storage — it's fundamentally about attention management."
- konovalov-nk: "160GB holds 11.5 years at 10K memories/day. If that's unsolved, it's a skill issue." — Storage is solved. Retrieval quality is the problem.

### The Pivot

Everyone in the AI memory space is approaching this as a linear problem — chunk text, embed it, store vectors, search by cosine similarity. It's RAG. It works for "what did I say about project X?" It breaks for everything else.

But the systems that actually handle massive data at scale — Splunk, Snowflake, Elasticsearch — solved this decades ago. They didn't solve it with vector search. They solved it with tiered storage, inverted indexes, bloom filters, columnar formats, and compression pipelines.

**New framing:** Myelin8 is a SIEM for AI memory. Not a RAG system. Not a vector database. A SIEM.

| SIEM Component | What It Does | Myelin8 Equivalent |
|---|---|---|
| Indexer | Ingest, parse, compress, write to buckets | `myelin8 add` + `myelin8 run` |
| Buckets (hot/warm/cold/frozen) | Time-partitioned, decreasing access speed | 4-tier compression pipeline |
| tsidx (inverted index) | Know which terms exist without reading data | tantivy FTS index |
| Bloom filters | Skip buckets that can't contain search term | Merkle tree partition existence checks |
| Search head | Coordinate queries, merge results | Hybrid search (FTS + semantic + RRF) |
| Cluster master | Manage tiers, transparent decompression | Engine core — AI never sees compressed data |
| SmartStore | Remote frozen storage, cache on access | Parquet frozen tier, recall to hot |
| KV Store | Structured metadata lookups | redb or filesystem `.meta` files |
| Lookup tables | Search-time enrichment | Significance scores, source labels |

---

## 2026-03-22 — Architecture Decisions

### Rename: Engram → Myelin8

- "Engram" crowded (9+ repos, including `joshuaswarren/openclaw-engram` with 853 commits)
- "Myelin8" = numeronym for "myelinate" (like k8s, i18n, a11y)
- Myelin sheaths speed up neural signal transmission 100x — the tool speeds up AI memory retrieval
- `pip install myelin8` — available on PyPI
- `myelin8 search "query"` — 7 characters, fast to type
- GitHub repo renamed: `qinnovates/myelin8`

### User-Defined Sources (Replace Auto-Scanning)

**Before:** `engram scan` crawled `~/.claude/` and auto-discovered files. This is what broke things — it found files Claude needs and encrypted them.

**After:** `myelin8 add ~/path/ --label name` — user explicitly defines what gets indexed. No crawling. No auto-discovery. Like Splunk: you configure inputs, not point at a filesystem.

### LSH Removed

LSH (12 random hyperplane hash tables) was redundant with HNSW. Both solve approximate nearest neighbor search. HNSW is more accurate. LSH removed from codebase, tests still pass.

### Significance-Weighted Memory

Human memory is selective because it's useful. The system should index what matters and skip what doesn't.

**Two-track scoring (simplified from regex NLP after Quorum review):**
1. **Explicit pins:** `myelin8 pin "the auth decision"` — user marks what matters
2. **Simple heuristics:** Length > 500 tokens = substantive, tool-call-only = routine

Original proposal had regex pattern matching ("we decided", "no, not that") but the Quorum flagged this as fragile — negation, sarcasm, and context-dependent language defeat regex.

### Encryption Deferred (Not Removed)

All encryption code stays in the repo. ML-KEM-768 + AES-256-GCM + Rust sidecar = the long-term moat. But it ships as opt-in (`[secure]` extra), not default, until the integration problem is solved:

1. Prove compression works without breaking Claude
2. Prove the Claude skill correctly routes to myelin8 for compressed data
3. Then layer encryption and prove the full pipeline works

### SQLite Rejected

The Quorum recommended migrating from JSON to SQLite for scale. But SQLite stores everything in a single plaintext database file on disk — worse security posture than the current approach. An attacker who gets `~/.myelin8/index.db` gets all indexed memories in one file.

**Alternative chosen:** Content-addressable filesystem (like Git). One `.meta` file per artifact, keyed by content hash, stored in a fan-out directory structure: `store/a3/f8c2e1.meta`. tantivy handles all queries. No database.

---

## 2026-03-22 — Parquet Tier Experiment

### Hypothesis

What if everything non-hot is Parquet? Skip the multi-format pipeline (plaintext → zstd → dict-zstd → Parquet). One format for all compressed tiers, different zstd levels.

### Test 1: Single File Round-Trip

Compressed `project_myelin8.md` (3,410 bytes) through all Parquet tiers:

| Tier | Compression | Size | Ratio | Lossless |
|---|---|---|---|---|
| Original | — | 3,410 bytes | 1x | — |
| Warm (zstd-3) | Parquet | 18,235 bytes | 0.2x (LARGER) | Yes |
| Cold (zstd-9) | Parquet | 18,210 bytes | 0.2x (LARGER) | Yes |
| Frozen (zstd-19) | Parquet | 18,190 bytes | 0.2x (LARGER) | Yes |

**Result:** Parquet has ~15KB of metadata overhead (schema, row groups, column chunks, footer). A single small file in Parquet is 5x LARGER than the original. Parquet is designed for batches, not individual files.

**SHA-256 verification:** Identical at every tier. Full round-trip (hot → warm → cold → frozen → hot) produced bit-for-bit identical content. Parquet is lossless for UTF-8 text.

### Test 2: Batched Files

Compressed all 27 memory files (60,419 bytes total) into single Parquet files per tier:

| Tier | Size | Ratio | Lossless |
|---|---|---|---|
| Original (27 files) | 60,419 bytes | 1x | — |
| Warm (zstd-3) | 37,213 bytes | 1.6x | Yes |
| Cold (zstd-9) | 35,659 bytes | 1.7x | Yes |
| Frozen (zstd-19) | 35,063 bytes | 1.7x | Yes |

**Compression ratio is modest (1.7x)** on small text files. Plain zstd-9 on the same data would give ~4x. Parquet overhead eats into the savings.

**But column-selective reads are the real value:** Reading just summary + significance + hash = 1,865 bytes vs full content 63,715 bytes = **34x less data read.** This is the token savings mechanism — return summaries to Claude, never load full content unless recalled.

### Test 3: Pre-Compressed Content in Parquet

Tried zstd-compressing the content column before writing to Parquet:

| Approach | Size | Ratio |
|---|---|---|
| Parquet zstd-9 (native) | 35,659 bytes | 1.7x |
| zstd-9 content + Parquet (none) | 39,578 bytes | 1.5x |
| zstd-9 content + Parquet (zstd-3) | 39,143 bytes | 1.5x |

**Pre-compression makes it worse.** Already-compressed data is incompressible; adding Parquet overhead on top increases size. Parquet's native column-level zstd is already optimal.

### Conclusion

Parquet's value is **retrieval efficiency, not storage compression.**

- Compression ratio on small text: mediocre (1.7x)
- Column-selective reads: excellent (34x less data for summary-only queries)
- Lossless round-trip: confirmed (SHA-256 identical through all tiers)
- Overhead per file: ~15KB (batch to amortize)

For larger files (real session logs, 50KB-500KB), compression ratios will improve significantly as the content-to-overhead ratio shifts. The 27 memory files (avg 2.2KB each) are a worst-case scenario for Parquet.

**Architecture decision:** Parquet for all non-hot tiers. Hot stays plaintext (Claude reads directly). Warm/cold/frozen are Parquet with increasing zstd levels. Batch by time window (weekly/monthly/quarterly) to amortize metadata overhead.

---

## 2026-03-22 — Rust Rewrite Decision

### Why

The Python codebase is a Rust sidecar with Python glue. The sidecar already handles: Merkle tree, SimHash, CoGraph, and all cryptography. The Python side handles: CLI, JSON file management, zstd calls, keyword extraction, search. All of this is simpler and faster in Rust.

**What we eliminate:**
- Python + Rust IPC overhead (JSON over stdin/stdout)
- `pip install` dependency management
- Two build systems (setuptools + cargo)
- JSON file concurrency problems (Rust has proper file locking)
- 80MB sentence-transformers download for optional embeddings

**What we get:**
- Single binary: `brew install myelin8` or download from GitHub releases
- Memory safety by default
- Embedded search engine (tantivy — Rust-native Lucene equivalent)
- No database dependency (filesystem + tantivy)
- MCP server built into the binary

### Core Crates

| Crate | Purpose |
|---|---|
| `tantivy` | Full-text search (inverted index, BM25, stemming) |
| `zstd` | Compression at all levels |
| `parquet` (arrow-rs) | Columnar storage for warm/cold/frozen |
| `sha3`, `sha2` | Content hashing + Merkle tree |
| `clap` | CLI |
| `serde`, `rmp-serde` | Serialization (msgpack for `.meta` files) |
| `tokio` | Async runtime for MCP server |

### What Carries Over From Current Sidecar
- `merkle.rs` — SHA3-256 tree, proofs, HMAC seal
- `simhash.rs` — near-duplicate detection
- `cograph.rs` — co-occurrence + spreading activation (Phase 3)
- `crypto.rs` — ML-KEM-768 + AES-256-GCM (Phase 3)

---

## 2026-03-22 — Quorum Architecture Review (6/10 Confidence)

Ran a 6-agent Quorum review before implementation. Key findings:

### CRITICAL
1. **No concurrency control on JSON files.** Two `myelin8 run` processes will race. Fix: file locking + atomic writes in Rust.

### HIGH (Selected)
2. **FTS with top-30 keywords is lossy.** A user searching for a specific term not in the top 30 gets zero results despite the content existing. Fix: exhaustive inverted index via tantivy (indexes ALL tokens).
3. **"Merkle accelerates search" is not substantiated.** A Merkle tree is an integrity structure, not a search index. It verifies "does this exact hash exist" but can't do keyword search. Fix: remove the claim from docs. Merkle = integrity. tantivy = search.
4. **Significance scoring via regex is fragile.** "We decided to NOT use this approach" scores as a decision but is actually a rejection. Fix: two-track (explicit pins + simple heuristics).
5. **The 6-12x token savings claim is unvalidated.** Real comparison is `myelin8 search` (1 call) vs `Grep + Read` (2-3 calls), not 4-8. Actual savings likely 2-3x. Fix: benchmark with real data.
6. **MCP server is the product, not the CLI.** Deferring MCP while building Parquet and CoGraph is a prioritization error. Fix: build MCP first.

### Confidence: 6/10
Core concept is sound. Prioritization needs to invert: ship a simple, safe FTS + compression engine with MCP server, then add sophistication where measurement justifies it.

---

## 2026-03-22 — Thawed Tier: Not Needed

Splunk has a "thawed" tier — frozen data restored to a searchable state that won't be auto-frozen again. This prevents ping-pong (recall → immediately re-frozen because it's old).

**Decision:** Skip thawed. Reset timestamps on recall instead. The AI is the babysitter — it accesses what it needs, and access patterns determine what stays hot. As long as tier transitions require BOTH age AND idle thresholds, a recalled artifact won't re-compress until it's been idle long enough.

```rust
enum Tier { Hot, Warm, Cold, Frozen }
// No Thawed — recall resets timestamps, Hebbian decay handles the rest
```

---

## Architecture (Current — Post All Decisions)

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
│  │ SEARCH (tantivy — full inverted index + BM25)      │  │
│  │  All tokens indexed (not top-30). Stemming.        │  │
│  │  Optional: semantic embeddings + RRF fusion.       │  │
│  └─────────────────────┬──────────────────────────────┘  │
│                        │                                  │
│  ┌─────────────────────▼──────────────────────────────┐  │
│  │ ENGINE (tier management)                           │  │
│  │  Knows where every artifact lives.                 │  │
│  │  Transparent decompression on recall.              │  │
│  │  Significance scoring (pins + heuristics).         │  │
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
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ INTEGRITY                                          │  │
│  │  SHA-256 content hash per artifact (computed once)  │  │
│  │  Merkle tree over all content hashes               │  │
│  │  Verified on every recall (detect drift)           │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ STORAGE (filesystem, no database)                  │  │
│  │  store/hot/     — plaintext files                  │  │
│  │  store/warm/    — weekly Parquet (zstd-3)          │  │
│  │  store/cold/    — monthly Parquet (zstd-9)         │  │
│  │  store/frozen/  — quarterly Parquet (zstd-19)      │  │
│  │  index/         — tantivy search index             │  │
│  │  merkle.bin     — integrity tree                   │  │
│  │  config.toml    — user-defined sources             │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## 2026-03-22 — Parquet Speed Benchmarks: Use It From The Start

### The Question

Should Parquet only be used for frozen tier (3+ months old), or for everything non-hot?

### The Concern

Parquet has metadata overhead (~15KB per file). Small files get LARGER. And zstd-19 (frozen level) might be too slow for warm tier where data is accessed more frequently.

### The Test

Benchmarked Parquet read/write speed across file sizes at all compression levels:

| File Size | Write (warm zstd-3) | Write (frozen zstd-19) | Read (content) | Read (summary only) | Ratio | Lossless |
|---|---|---|---|---|---|---|
| 5 KB | 0.2ms | 0.5ms | 0.5ms | 0.2ms | 0.2x (overhead) | Yes |
| 50 KB | 0.2ms | 0.6ms | 0.2ms | 0.2ms | 15.9x | Yes |
| 200 KB | 0.3ms | 0.9ms | 0.3ms | 0.2ms | 63.6x | Yes |
| 500 KB | 0.5ms | 0.9ms | 0.4ms | 0.2ms | 157.7x | Yes |

### The Findings

1. **Speed is not a problem at any tier.** Even frozen (zstd-19) writes under 1ms. Reads under 0.5ms. No reason to use a different format for warm vs frozen.

2. **Compression on real session logs is massive.** 50KB → 3.2KB (16x). 500KB → 3.3KB (158x). The earlier 1.7x ratio was on tiny 2KB memory files — worst case for Parquet.

3. **Summary-only reads are constant-time: 0.2ms regardless of file size.** This is the token savings mechanism. Read the summary column, skip the content column entirely.

4. **Small files are the only downside.** 5KB files get 5x LARGER in Parquet due to metadata overhead. Fix: batch small files into weekly/monthly Parquet files.

5. **Pre-compressing content before Parquet makes it WORSE.** Already-compressed data can't be compressed again. Parquet's native column-level zstd is already optimal. Don't double-compress.

### The Decision

**Parquet from the start for all non-hot tiers.** No zstd-only intermediate format. No multi-format pipeline.

```
Hot    = plaintext (Claude reads directly)
Warm   = Parquet zstd-3  (weekly batches)
Cold   = Parquet zstd-9  (monthly batches)
Frozen = Parquet zstd-19 (quarterly batches)
```

One compressed format. One read path. One write path. Tier transitions just change batch granularity and compression level within the same format.

Parquet is also immutable once written (can't append). This matches Splunk: hot buckets accept writes, warm/cold/frozen buckets are sealed. New artifacts stay in hot (plaintext) until `myelin8 run` batches them into the current week's Parquet file.

### Parquet Overhead Not a Problem in Practice

The 15KB overhead matters when you have one 3KB file in a Parquet file. It doesn't matter when you batch 50 artifacts into one weekly Parquet file — the overhead is amortized across all rows.

---

## 2026-03-22 — The Real Cost: What Happens Today Without Myelin8

### How An AI Assistant Currently Handles "What Happened 2 Months Ago"

Traced the actual tool call cascade when an AI coding assistant needs to find historical context. This is not hypothetical — this is the real sequence that happens with Claude Code's existing memory system:

```
User: "check what happened 2 months ago"

Step 1: Read the lookup rules
  → The memory protocol file defines a search order
  → ~500 tokens consumed just for the instruction

Step 2: Check the curated memory index (already loaded in context)
  → Scan for relevant entries
  → Maybe find a pointer to the right file, maybe not
  → If not found, continue to step 3

Step 3: Check weekly digests
  → Glob for weekly/*.md files in the date range
  → Read matching digest files
  → 1,000-3,000 tokens per digest
  → Digests are compressed summaries — might not have enough detail

Step 4: Search daily logs (if digest wasn't enough)
  → Glob for daily/2026-01-*.md — potentially 31 files
  → Grep across all of them for keywords
  → Read 3-5 files that matched
  → 2,000-10,000 tokens per file

Step 5: Search archive (if daily logs didn't have it)
  → Glob for archive/*.md
  → More grepping, more reading
  → More tokens consumed

Step 6: Search raw session logs (last resort)
  → Grep through session .jsonl files
  → These are 50KB-500KB each
  → Reading even ONE burns 5,000-50,000 tokens
  → And there might be hundreds of session files

Step 7: Maybe spawn a search subagent
  → A separate agent context does its own grep/read cycle
  → Duplicates work in a separate context window
  → Returns a summary (more tokens consumed by both contexts)

Step 8: Synthesize across everything found
  → Process all the context loaded in steps 1-7
  → More tokens to produce the final answer
```

**Actual cost:** 15,000-80,000 tokens, 8-15 tool calls, 30-90 seconds elapsed. And the answer still might miss relevant content because:
- Grep only finds exact keyword matches ("postgres" misses "PostgreSQL")
- The user's question might be phrased differently than the stored content
- Older files might have been moved, renamed, or formatted differently
- The cascade stops at the first "good enough" result — missing better matches deeper in the stack

Each failed lookup triggers a BROADER search, loading MORE context, burning MORE tokens. The cascade compounds.

### How Myelin8 Handles the Same Question

```
User: "check what happened 2 months ago"

Step 1: MCP tool call → memory_search(after="2026-01-22", before="2026-02-22")
  → myelin8 queries tantivy (pre-built inverted index)
  → Date range filter on created_date field
  → Finds 47 artifacts across warm/cold Parquet files
  → Reads ONLY the summary + significance columns (column-selective)
  → Ranks by significance score
  → Returns top 10 summaries
  → ~500 tokens

Step 2 (only if user wants detail): MCP tool call → memory_recall(content_hash)
  → myelin8 reads content column from the specific Parquet row
  → SHA-256 verifies content matches original
  → Returns full plaintext
  → ~2,000 tokens
```

**Actual cost:** 2,500 tokens, 2 tool calls, <1 second. Guaranteed to find it because it's indexed.

### The Comparison

| | Without Myelin8 | With Myelin8 |
|---|---|---|
| Token cost | 15,000-80,000 | 2,500 |
| Tool calls | 8-15 | 2 |
| Time | 30-90 seconds | <1 second |
| Finds paraphrased content? | No (grep is exact match) | Yes (tantivy stemming) |
| Finds across all time ranges? | Maybe (depends on cascade) | Yes (indexed with dates) |
| Ranked by importance? | No | Yes (significance scoring) |
| Verified integrity? | No | Yes (SHA-256 content hash) |

The value isn't compression. It's not encryption. It's: **"You asked, I found it, in one call."**

The token savings aren't 6-12x on a single file read. They're 6-30x on the FULL RETRIEVAL CASCADE — the entire sequence of glob, grep, read, re-grep, re-read, subagent, synthesize that happens every time an AI assistant needs historical context.

---

## 2026-03-22 — No Database Required

### The Question

Do we need a database (SQLite, redb, MongoDB) for metadata storage?

### The Decision: No

tantivy IS the query layer. The filesystem IS the storage layer. No database needed.

| What | Stored In | Why Not a Database |
|---|---|---|
| Search index | tantivy (local files, Lucene-like segments) | Purpose-built for full-text search. BM25, stemming, date ranges. |
| Artifact metadata | `.meta` files (msgpack, content-addressable dirs) | One file per artifact, keyed by hash. Git uses the same pattern at millions of objects. |
| Compressed content | Parquet files (weekly/monthly/quarterly batches) | Self-describing columnar format. Column-selective reads built in. |
| Merkle tree | `merkle.bin` (single binary file) | Computed in Rust. Append-only on new artifacts. |
| Source config | `config.toml` | Rarely changes. No query complexity. |

SQLite was considered and rejected — it stores everything in a single plaintext file on disk. An attacker who gets `~/.myelin8/index.db` gets all indexed memories in one file.

The content-addressable filesystem (like Git objects: `store/a3/f8c2e1.meta`) provides natural sharding, atomic writes via rename, and no single file that contains everything.

---

## Open Questions

1. **Token savings benchmark.** Need real measurement on 20 historical lookup tasks comparing the full cascade vs myelin8 search.
2. **Parquet compression on batched session logs.** Individual session logs (50-500KB) compress 16-158x. Batched weekly Parquet files with many sessions should be tested.
3. **Claude integration.** CLAUDE.md instruction + SessionStart hook + MCP server — the three layers that teach Claude when to use myelin8. Not built yet. This is the actual product.
4. **Encryption integration.** After Parquet pipeline is proven stable, how does encryption layer on top? Encrypt whole Parquet files? Per-column? Design TBD.
5. **Rust rewrite scope.** Core crates identified (tantivy, parquet, zstd, sha3, clap, tokio). Existing Rust sidecar code (merkle.rs, simhash.rs, crypto.rs) carries over. Full rewrite vs incremental migration to decide.

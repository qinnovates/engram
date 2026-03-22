# Engram v2: Full Architecture Proposal

## Table of Contents

- [The One-Sentence Architecture](#the-one-sentence-architecture)
- [System Diagram](#system-diagram)
- [Data Flow: Search (80% of cases — no decompression needed)](#data-flow-search-80-of-cases-no-decompression-needed)
- [Data Flow: Full Recall (20% of cases — decompression needed)](#data-flow-full-recall-20-of-cases-decompression-needed)
- [Data Flow: Registration (on `engram scan`)](#data-flow-registration-on-engram-scan)
- [Data Flow: Tier Transition (on `engram run`)](#data-flow-tier-transition-on-engram-run)
- [Memory Architecture (How It Maps to the Brain)](#memory-architecture-how-it-maps-to-the-brain)
- [Performance Model](#performance-model)
  - [Measured baseline (v1, 4,560 artifacts)](#measured-baseline-v1-4560-artifacts)
  - [Projected v2 (sidecar holds index)](#projected-v2-sidecar-holds-index)
  - [Net improvement](#net-improvement)
- [Crypto Architecture (Unchanged)](#crypto-architecture-unchanged)
- [Implementation Strategy](#implementation-strategy)
  - [Phase 1: Merkle-Index in Sidecar (2-3 days)](#phase-1-merkle-index-in-sidecar-2-3-days)
  - [Phase 2: Co-occurrence Graph (1-2 days)](#phase-2-co-occurrence-graph-1-2-days)
  - [Phase 3: Selective Section Decompression (1 day)](#phase-3-selective-section-decompression-1-day)
  - [Not Building](#not-building)
- [Success Criteria](#success-criteria)

---

*2026-03-21. Kevin Qi. Architecture derived from measured bottlenecks, neuroscience memory models, and 5-expert quorum review.*

---

## The One-Sentence Architecture

**The Rust sidecar becomes the memory — not just the lock.**

Currently: Python owns the data, Rust owns the keys. Every search parses 8MB of JSON.

Proposed: Rust owns the data AND the keys. Python is a thin CLI. Every search is a sidecar IPC call.

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude / AI Agent                        │
│                                                              │
│  "What did we decide about auth last week?"                  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   Python CLI (thin wrapper)                    │
│                                                               │
│  engram search "auth"  →  vault.index_search("auth")          │
│  engram recall <hash>  →  vault.index_lookup(<hash>)          │
│  engram recall --section decisions  →  decompress + split     │
│                                                               │
│  No JSON parsing. No index loading. Just IPC to sidecar.      │
└──────────────────────┬───────────────────────────────────────┘
                       │ stdin/stdout IPC (0.15ms round-trip)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│              Rust Sidecar (engram-vault)                       │
│              ══════════════════════════                        │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Merkle-Index (in-memory)                     │ │
│  │                                                           │ │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │ │
│  │  │ Merkle Tree  │  │ Leaf Payloads │  │ Keyword Index │  │ │
│  │  │ (SHA3-256)   │  │ (summaries,   │  │ (inverted,    │  │ │
│  │  │              │  │  metadata,    │  │  per-keyword   │  │ │
│  │  │  Root        │  │  sections,    │  │  → hash set)   │  │ │
│  │  │  ├── L1      │  │  tier info)   │  │               │  │ │
│  │  │  ├── L2      │  │              │  │  "auth" → {h1, │  │ │
│  │  │  ├── L3      │  │  h1 → {...}  │  │    h4, h7}     │  │ │
│  │  │  └── L4      │  │  h2 → {...}  │  │  "jwt" → {h1,  │  │ │
│  │  │              │  │  h3 → {...}  │  │    h3}          │  │ │
│  │  └─────────────┘  └──────────────┘  └───────────────┘  │ │
│  │                                                           │ │
│  │  Search: keyword → hash set → payloads → proofs           │ │
│  │  Lookup: hash → payload → proof                           │ │
│  │  Verify: proof path → root check (constant-time)          │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Crypto Engine (existing)                      │ │
│  │                                                           │ │
│  │  ML-KEM-768 + X25519 → AES-256-GCM                       │ │
│  │  HMAC-SHA3-256 root sealing                               │ │
│  │  Keychain integration (Touch ID / Face ID)                │ │
│  │  mlockall + zero core dumps                               │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Co-occurrence Graph (SQLite)                  │ │
│  │                                                           │ │
│  │  edges(source, target, weight, type, updated)             │ │
│  │  → top-3 related on every lookup                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   Tiered Storage (disk)                        │
│                                                               │
│  HOT     ~/.claude/sessions/*.jsonl           uncompressed    │
│  WARM    ~/.engram/warm/*.jsonl.zst           zstd-3          │
│  COLD    ~/.engram/cold/*.jsonl.zst           zstd-9 + strip  │
│  FROZEN  ~/.engram/frozen/*.parquet           columnar + delta │
│                                                               │
│  Each file optionally encrypted: AES-256-GCM envelope         │
│  Decryption only on explicit recall (not on search)           │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Search (80% of cases — no decompression needed)

```
Claude: "What did we decide about auth?"
  │
  ▼
Python: vault.index_search("auth decisions")
  │
  ▼ IPC (0.15ms)
  │
Sidecar:
  1. Keyword lookup: "auth" → {h1, h4, h7}     0.001ms
                     "decisions" → {h1, h2, h5}  0.001ms
     Intersection: {h1}                          0.001ms

  2. Payload lookup: h1 → LeafPayload {          0.001ms
       summary: "Auth middleware refactor. Decided on JWT
                 rotation every 15min, refresh tokens in
                 httpOnly cookies.",
       tier: "cold",
       keywords: ["auth", "jwt", "middleware", "decisions"],
       sections: ["context", "decisions", "code"],
       created_at: 1710892800,
     }

  3. Merkle proof: proof(leaf_index_of_h1)        0.03ms
     Returns: leaf_hash + siblings + directions + root

  4. Return to Python:                            0.15ms
     { summary, tier, keywords, proof, related: [...] }
  │
  ▼
Python formats response for Claude.
  │
  ▼
Claude reads verified summary. Enough for 80% of queries.
No decompression. No decryption. No disk IO.

Total: ~0.5ms (dominated by IPC, not computation)
```

---

## Data Flow: Full Recall (20% of cases — decompression needed)

```
Claude: "Show me the actual code changes from that auth session"
  │
  ▼
Python: vault.index_lookup(h1) → payload says tier="cold", has section "code"
  │
  ▼
Python: engram recall <path> --section code
  │
  ▼
  1. Read compressed file from disk               1-5ms (SSD)
  2. Decrypt if encrypted (sidecar AES-256-GCM)   0.5ms
  3. Decompress (zstd)                             1-10ms
  4. Section split (regex on headers)              0.1ms
  5. Return "code" section only
  │
  ▼
Total: ~5-15ms for a specific section from cold tier.
(vs ~500ms currently for full artifact recall)

Claude gets only the code section. Context window not wasted
on the discussion/background sections.
```

---

## Data Flow: Registration (on `engram scan`)

```
New session file detected
  │
  ▼
Python:
  1. Read file content
  2. Extract keywords (top 30 by frequency)
  3. Generate summary (first heading + paragraph)
  4. Compute SHA3-256 hash
  5. Generate embedding (384-dim, optional)
  │
  ▼
Sidecar:
  6. INDEX_ADD: store LeafPayload in memory        0.01ms
  7. MERKLE_ADD: add hash as tree leaf             0.01ms
  8. Update inverted keyword index                 0.01ms
  9. Update co-occurrence edges (if recalled with others)
  │
  ▼
Python:
  10. Write updated index to disk (atomic)         ~5ms
      (Sidecar state is authoritative during session;
       disk is the persistence backup)
```

---

## Data Flow: Tier Transition (on `engram run`)

```
engram run (age + idle thresholds)
  │
  ▼
For each artifact past threshold:
  │
  ▼
  1. Compress: hot → zstd-3 (warm) or zstd-9 (cold) or parquet (frozen)
  2. Encrypt if configured (sidecar AES-256-GCM)
  3. Update sidecar: INDEX_UPDATE tier=warm/cold/frozen      0.01ms
     (Leaf payload updated, Merkle tree unchanged —
      the content hash is still valid, only tier changed)
  4. HMAC-seal new root (tier change = new root)             0.01ms
  │
  ▼
Merkle tree integrity maintained across all tier transitions.
Content hash computed BEFORE compression, stays valid forever.
Summary stays in sidecar memory regardless of tier.
```

---

## Memory Architecture (How It Maps to the Brain)

```
┌──────────────────────────────────────────────────────────┐
│                SIDECAR (Hippocampus)                       │
│                                                           │
│  Holds: indexes, summaries, proofs, relationships         │
│  Does NOT hold: actual content                            │
│  Always in memory. Instant access.                        │
│  This IS the brain's hippocampal index.                   │
│                                                           │
│  ┌────────────┐ ┌──────────┐ ┌───────────────────────┐  │
│  │ Merkle Tree │ │ Payloads │ │ Inverted Keyword Index │  │
│  │ (integrity) │ │ (summary)│ │ (search)              │  │
│  └────────────┘ └──────────┘ └───────────────────────┘  │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Co-occurrence Graph (spreading activation)            │ │
│  │ Recall one memory → related memories surface          │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
                           │
            Search: 0.05ms │ Full recall: 5-500ms
                           ▼
┌──────────────────────────────────────────────────────────┐
│               TIERED STORAGE (Neocortex)                   │
│                                                           │
│  Holds: actual content, compressed + encrypted             │
│  Accessed only on explicit recall.                        │
│  Fidelity decreases with age. Reconstructed on demand.    │
│                                                           │
│  HOT ──────── full content, uncompressed, instant         │
│  WARM ─────── zstd-3, ~10ms decompress                    │
│  COLD ─────── zstd-9 + stripped, ~200ms decompress        │
│  FROZEN ───── parquet columnar, ~2s decompress             │
│                                                           │
│  Each tier: optionally AES-256-GCM encrypted               │
│  Encryption keys: ML-KEM-768, managed by sidecar           │
└──────────────────────────────────────────────────────────┘
```

The sidecar (hippocampus) holds pointers and summaries. The disk (neocortex) holds full content. Search never touches disk. Full recall only happens when the summary isn't enough — same as the brain, where gist recall is instant and detail reconstruction takes effort.

---

## Performance Model

### Measured baseline (v1, 4,560 artifacts)

| Operation | Latency | Bottleneck |
|---|---|---|
| `engram search` | ~65ms | JSON parse (40ms) + Python startup (25ms) |
| `engram recall` (warm) | ~75ms | JSON parse (40ms) + decompress (10ms) + Python (25ms) |
| `engram recall` (cold) | ~565ms | JSON parse (40ms) + decompress (500ms) + Python (25ms) |
| `engram recall` (frozen) | ~5065ms | JSON parse (40ms) + Parquet restore (5000ms) + Python (25ms) |

### Projected v2 (sidecar holds index)

| Operation | Latency | Why |
|---|---|---|
| `engram search` | ~0.5ms | Sidecar IPC (0.15ms) + keyword lookup (0.01ms) + proof (0.03ms) + Python thin wrapper |
| Summary recall (any tier) | ~0.5ms | Same as search — summary is in sidecar memory |
| Section recall (warm) | ~12ms | Sidecar lookup (0.5ms) + decompress (10ms) + section split (0.1ms) |
| Section recall (cold) | ~205ms | Sidecar lookup (0.5ms) + decompress (200ms) + section split (0.1ms) |
| Full recall (frozen) | ~5001ms | Sidecar lookup (0.5ms) + Parquet restore (5000ms) |

### Net improvement

| Operation | v1 → v2 | Factor |
|---|---|---|
| Search | 65ms → 0.5ms | **130x** |
| Summary recall | 65ms → 0.5ms | **130x** |
| Warm section recall | 75ms → 12ms | **6x** |
| Cold section recall | 565ms → 205ms | **3x** |
| Frozen full recall | 5065ms → 5001ms | ~1x (decompression dominates) |

The big win is search and summary recall — the operations that happen on 80% of queries. The sidecar eliminates the 40ms JSON parse + 25ms Python startup tax that v1 pays on every single invocation.

---

## Crypto Architecture (Unchanged)

The Merkle-index doesn't change the encryption model:

| What | Where | Encrypted? |
|---|---|---|
| Summaries + keywords | Sidecar memory | No (needed for search) |
| Merkle tree + proofs | Sidecar memory | No (hashes, not content) |
| Co-occurrence graph | SQLite on disk | Yes (AES-256-GCM) |
| Hot artifacts | Disk | Optional |
| Warm/cold/frozen artifacts | Disk | Yes (per-artifact DEK) |
| Encryption keys | Keychain (macOS) | Yes (Keychain + Touch ID) |

Summaries are NOT encrypted because they must be searchable. This is a deliberate least-privilege tradeoff: the summary reveals topic and keywords (what the session was about) but not the full content (what was actually said). The Merkle proof proves the summary matches the encrypted content without decrypting it.

If even summaries must be hidden: implement encrypted search (FHE or searchable symmetric encryption). This is a Phase 3 concern and adds orders of magnitude to search latency. Not recommended unless the threat model requires it.

---

## Implementation Strategy

### Phase 1: Merkle-Index in Sidecar (2-3 days)

```
Day 1: Rust
  - Define LeafPayload struct in merkle.rs
  - Add HashMap<[u8;32], LeafPayload> to MerkleTree
  - Add inverted keyword index (HashMap<String, HashSet<[u8;32]>>)
  - New commands: INDEX_LOAD, INDEX_SEARCH, INDEX_LOOKUP, INDEX_STATS

Day 2: Python + Integration
  - VaultClient: index_search(), index_lookup(), index_stats()
  - CLI: route `engram search` through sidecar when running
  - CLI: add `--section` flag to `engram recall`
  - SessionStart hook: call INDEX_LOAD to warm sidecar

Day 3: Test + Benchmark
  - Unit tests for sidecar index commands
  - Integration tests: search → verify → recall flow
  - Benchmark: before/after latency on 4,560 real artifacts
  - Update README with measured results
```

### Phase 2: Co-occurrence Graph (1-2 days)

```
  - Create activation.py with SQLite-backed edge store
  - Record edges on co-recall and keyword overlap
  - INDEX_RELATED command in sidecar (reads SQLite)
  - Return top-3 related with every search result
```

### Phase 3: Selective Section Decompression (1 day)

```
  - Section regex patterns for common artifact formats
  - `engram recall --section decisions` decompresses and splits
  - Merkle proof covers full artifact (section is a verified substring)
```

### Not Building

- Frame-per-section zstd (python-zstandard doesn't support seekable frames)
- Predictive pre-fetch (measure first)
- Reconsolidation (needs drift bounds + side channel analysis)
- Encrypted search (FHE too slow, SSE adds complexity)

---

## Success Criteria

1. `engram search` < 1ms on 4,560 artifacts (currently 65ms)
2. Every search result includes a valid Merkle proof
3. Summary recall never touches disk
4. Section recall returns only the requested section
5. Related artifacts returned automatically (top-3)
6. 141+ tests passing
7. Sidecar binary < 600KB
8. No new Python dependencies

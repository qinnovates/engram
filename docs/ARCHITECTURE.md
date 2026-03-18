# Engram Architecture

Detailed documentation of how Engram works, what gets encrypted, how logging operates, and how each component is secured.

---

## Table of Contents

- [Overview](#overview)
- [Data Flow](#data-flow)
- [Registration and Indexing](#registration-and-indexing)
- [Tier Transitions](#tier-transitions)
- [Compression Pipeline](#compression-pipeline)
- [Search and Retrieval](#search-and-retrieval)
- [HNSW Vector Index](#hnsw-vector-index)
- [Hybrid Search](#hybrid-search)
- [Recall](#recall)
- [Encryption](#encryption)
- [What Gets Encrypted](#what-gets-encrypted)
- [Index Encryption](#index-encryption)
- [Rust Crypto Sidecar](#rust-crypto-sidecar)
- [Key Management](#key-management)
- [Audit Logging](#audit-logging)
- [Lookup Tables](#lookup-tables)
- [Embedding Architecture](#embedding-architecture)
- [File Permissions](#file-permissions)
- [Threat Model](#threat-model)

---

## Overview

Engram is a tiered memory compression engine that models how the brain stores information. It has four tiers (hot, warm, cold, frozen), a semantic index for search, and optional post-quantum encryption.

Every component is designed around two principles:
1. **Don't recompute what you can store and look up.** Every retrieval path uses precomputed lookup tables.
2. **Private keys never enter Python.** All crypto operations go through a compiled Rust sidecar.

---

## Data Flow

```
AI session files (Claude, ChatGPT, Cursor, Copilot)
         │
    engram scan
         │
         ▼
  ┌─ REGISTRATION ────────────────────────────────┐
  │  SHA-256 hash │ keyword extraction │ summary   │
  │  embedding generation │ HNSW insert │ LSH hash │
  └───────────────────────────────────────────────┘
         │
    engram run (age + idle thresholds)
         │
         ▼
  ┌─ TIER TRANSITIONS ───────────────────────────┐
  │  HOT ──1 week──▶ WARM ──1 month──▶ COLD      │
  │                                ──3 months──▶  │
  │                                    FROZEN     │
  └───────────────────────────────────────────────┘
         │
    engram search / engram context
         │
         ▼
  ┌─ RETRIEVAL (no decompression) ───────────────┐
  │  keyword lookup → LSH hash → HNSW graph      │
  │  → reciprocal rank fusion → rerank           │
  │  → return summaries to AI                    │
  └───────────────────────────────────────────────┘
         │
    engram recall (only when full content needed)
         │
         ▼
  ┌─ RECALL ──────────────────────────────────────┐
  │  decrypt (Rust sidecar + Touch ID)            │
  │  → decompress (pipeline reversal)             │
  │  → integrity check (SHA-256)                  │
  │  → return to hot tier                         │
  └───────────────────────────────────────────────┘
```

---

## Registration and Indexing

When an artifact is first discovered, Engram builds a complete index entry before any compression:

| Step | What's Created | Stored In |
|------|---------------|-----------|
| SHA-256 hash | Integrity fingerprint (quantum-safe: Grover reduces to 128-bit, above NIST SP 800-57 minimum) | `artifact-registry.json` |
| Keyword extraction | Top 30 keywords by frequency | `semantic-index.json` |
| Summary generation | First heading + paragraph (md), field names + count (jsonl) | `semantic-index.json` |
| Embedding (if enabled) | 384-dim vector via all-MiniLM-L6-v2 | `embeddings-hot.npy` |
| HNSW insert | Nearest-neighbor graph entry | `hnsw-hot.bin` |
| LSH hash | Hash bucket assignment for O(1) lookup | `lsh-tables.npz` |
| Timestamps | Created, last accessed, last modified | `artifact-registry.json` |

Gzip-compressed files (`.jsonl.gz` from Claude) are decompressed in memory for indexing. The file on disk stays compressed.

---

## Tier Transitions

| Transition | Age Threshold | Idle Threshold |
|-----------|--------------|----------------|
| Hot → Warm | 1 week | 3 days |
| Warm → Cold | 1 month | 2 weeks |
| Cold → Frozen | 3 months | 1 month |

Both conditions (age AND idle) must be met. All thresholds configurable in `config.json`.

### Full warm transition walkthrough

```
File: session-2025-09-12.jsonl (1.5 MB)
  Age: 8 days (> 1 week threshold)
  Idle: 5 days (> 3 days threshold)
  Decision: HOT → WARM

  ├─ Pipeline reads raw content
  │
  ├─ Stage 1: JSON minification
  │   Strip whitespace, shorten formatting
  │   1.5 MB → 1.0 MB (33% removed)
  │
  ├─ Stage 2: zstd level 3 compression
  │   1.0 MB → 340 KB (4.4x from original)
  │
  ├─ Stage 3 (if encryption enabled):
  │   In-process Rust encrypt with warm tier's public key
  │   ML-KEM-768 + X25519 hybrid KEM → AES-256-GCM
  │   340 KB → 342 KB (.encf file)
  │   Public key only — no private key needed to encrypt
  │
  ├─ Original file deleted (or kept if keep_originals=true)
  │
  ├─ Metadata updated:
  │   tier=warm, compressed_path=session.jsonl.zst.encf
  │
  ├─ Embedding truncated:
  │   384d float32 → 256d float32 (Matryoshka — drop last 128 dims)
  │
  ├─ HNSW entry moved from hot graph to warm graph
  │
  └─ Index entry updated: tier=warm
```

### Full cold transition walkthrough

```
Warm artifact: session.jsonl.zst.encf (342 KB compressed+encrypted)
  Age: 5 weeks (> 1 month threshold)
  Idle: 3 weeks (> 2 weeks threshold)
  Decision: WARM → COLD

  ├─ Decrypt (if encrypted):
  │   Rust sidecar retrieves warm private key from Keychain
  │   Key held in Zeroizing<T> wrapper in mlock'd memory
  │   In-process ML-KEM-768 + X25519 decapsulation → HKDF-SHA256 → AES-256-GCM decrypt
  │   Zeroizing drop fires on all exit paths (including errors and panics)
  │   342 KB → 340 KB (.zst file)
  │
  ├─ Decompress warm zstd back to raw content
  │   340 KB → 1.0 MB (minified JSON)
  │
  ├─ Stage 1: Boilerplate stripping
  │   The 3,000-token system prompt repeated in every session:
  │     "You are Claude, an AI assistant. <system-reminder>..."
  │   Replaced with: BOILERPLATE_REF:a3f7b2e1 (64 bytes)
  │   Original stored once in ~/.engram/boilerplate/a3f7b2e1.boilerplate
  │   Content reduced by 40-70%
  │   1.0 MB → 400 KB
  │
  ├─ Stage 2: JSON minification (cleanup pass)
  │
  ├─ Stage 3: Dictionary-trained zstd level 9
  │   The compression dictionary (112 KB, trained on your 500 sessions)
  │   already knows your JSON schema, common tokens, tool call formats.
  │   It only compresses what's actually unique to this session.
  │   400 KB → 150 KB (10x from original)
  │
  ├─ Stage 4 (if encryption):
  │   In-process Rust encrypt with cold tier's public key
  │   ML-KEM-768 + X25519 hybrid KEM → AES-256-GCM
  │   Different keypair than warm — compromise warm, cold stays safe
  │
  ├─ Embedding truncated:
  │   256d float32 → 128d int8 quantized (4x smaller)
  │
  ├─ HNSW entry moved to cold graph
  │
  └─ PQ codebook encodes the embedding:
      128 dims → 8 uint8 centroid indices (8 bytes)
```

### Full frozen transition walkthrough

```
Cold artifact: session.jsonl.cold.zst.encf (152 KB compressed+encrypted)
  Age: 4 months (> 3 months threshold)
  Idle: 6 weeks (> 1 month threshold)
  Decision: COLD → FROZEN

  ├─ Decrypt cold artifact (sidecar in-process crypto + cold private key)
  │
  ├─ Decompress cold zstd (using trained dictionary)
  │
  ├─ Restore boilerplate references:
  │   BOILERPLATE_REF:a3f7b2e1 → look up in boilerplate store
  │   → full system prompt text restored
  │
  ├─ Stage 1: Boilerplate strip (fresh pass for frozen pipeline)
  │
  ├─ Stage 2: Minify JSON
  │
  ├─ Stage 3: Columnar Parquet conversion
  │   JSONL rows:
  │     {"role":"user","content":"What about auth?","timestamp":1710000000}
  │     {"role":"assistant","content":"Here's my analysis...","timestamp":1710000060}
  │     {"role":"user","content":"And the JWT flow?","timestamp":1710000120}
  │
  │   Transposed to columns:
  │     role column:      ["user","assistant","user","assistant",...]
  │       → cardinality 2 → run-length encoding → ~0 bytes
  │     timestamp column: [1710000000, 1710000060, 1710000120,...]
  │       → monotonically increasing → delta encoding → ~0 bytes
  │       (deltas are [60, 60, 60,...] → single value repeated)
  │     content column:   actual conversation text
  │       → dictionary encoded + zstd level 19
  │       → this is the only column with real entropy
  │
  │   Result: 50 KB (30x from original 1.5 MB)
  │
  ├─ Stage 4 (if encryption):
  │   In-process Rust encrypt with frozen tier's public key
  │   ML-KEM-768 + X25519 hybrid KEM → AES-256-GCM
  │   Third independent keypair
  │
  ├─ Embedding truncated:
  │   128d int8 → 64d binary via numpy.packbits
  │   96 bytes per artifact
  │   Searched via Hamming distance (CPU popcount instruction)
  │
  └─ LSH hash updated for O(1) frozen-tier lookup
```

---

## Search and Retrieval

Search never decompresses artifacts. It operates entirely on the precomputed index. When embeddings are available (`pip install engram[embeddings]`), search uses hybrid retrieval. Without embeddings, it falls back to keyword-only.

### Full retrieval flow

```
Query: "authentication refactor"
  │
  ├─ Layer 1: KEYWORD LOOKUP TABLE — O(1) per keyword
  │   Inverted index in semantic-index.json:
  │     "authentication" → [artifact_42, artifact_891, artifact_2204]
  │     "refactor" → [artifact_42, artifact_155, artifact_891]
  │   Intersection: [artifact_42, artifact_891]
  │   Cost: O(1) hash lookup per keyword
  │
  ├─ Layer 2: LSH HASH TABLE — O(1)
  │   Hash the query embedding with 12 random hyperplanes
  │   across 4 independent hash tables (4096 buckets each)
  │   hash(query_embedding) → bucket_7294
  │   bucket_7294 contains: [artifact_42, artifact_891, artifact_3001]
  │   Cost: O(1) hash + O(bucket_size) scan
  │
  ├─ Layer 3: HNSW GRAPH — O(log n) per tier
  │   Navigate nearest-neighbor graph at each tier's dimension:
  │     Hot graph (384d float32): top matches from recent files
  │     Warm graph (256d float32): top matches from last month
  │     Cold graph (128d int8): top matches from older files
  │     Frozen (64d binary): Hamming distance via popcount
  │   Top-5: [artifact_42, artifact_891, artifact_3001, artifact_155, artifact_7]
  │   Cost: O(log n) per tier
  │
  ├─ Layer 4: RECIPROCAL RANK FUSION
  │   Merge keyword results + vector results:
  │   RRF_score(artifact) = Σ(1/(60 + rank_i)) for each ranked list
  │   Dedup by artifact path (same artifact found by both searches)
  │   Sort by combined RRF score
  │   Cost: O(results) — trivial
  │
  ├─ Layer 5: RERANK (optional)
  │   Top results re-scored with full cosine similarity
  │   on original embeddings (not the truncated tier versions)
  │   Cost: O(top_k) — only on the final result set
  │
  └─ Output: ranked list of artifacts with summaries
     The AI sees summaries at 10-20% of token cost
     Full content available via engram recall <path>
```

No decompression happened. The index, embeddings, and graphs are always in memory. The compressed files on disk were never touched.

---

## HNSW Vector Index

Each tier maintains its own Hierarchical Navigable Small World (HNSW) graph at its native embedding dimension. This gives O(log n) approximate nearest neighbor search instead of O(n) linear scan.

### Per-tier graphs

| Tier | Dimension | File | Backend |
|------|-----------|------|---------|
| Hot | 384-d float32 | `hnsw-hot.bin` | hnswlib (or numpy fallback) |
| Warm | 256-d float32 | `hnsw-warm.bin` | hnswlib (or numpy fallback) |
| Cold | 128-d float32 | `hnsw-cold.bin` | hnswlib (or numpy fallback) |
| Frozen | 64-d float32 | `hnsw-frozen.bin` | hnswlib (or numpy fallback) |

### HNSW parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `M` | 16 | Connections per node (balances recall vs memory) |
| `ef_construction` | 200 | Build-time quality (higher = better graph, slower build) |
| `ef` | 50 | Search-time quality (higher = better recall, slower search) |
| `space` | cosine | Similarity metric for float embeddings |

### Graceful fallback

When `hnswlib` is not installed (`pip install hnswlib`, ~1.3 MB, no server), the index falls back to brute-force numpy cosine similarity. Same API, same results, just O(n) instead of O(log n). The backend is auto-detected at import time.

### Tier transitions

When an artifact moves tiers, its embedding is truncated (Matryoshka) and re-inserted into the new tier's graph. The old tier entry is removed. On recall, the embedding is restored to full 384-d and re-inserted into the hot graph.

---

## Hybrid Search

When embeddings are available, search uses hybrid retrieval combining keyword search (BM25-style from `SemanticIndex`) with vector search (HNSW + LSH) via Reciprocal Rank Fusion. Without embeddings, it falls back to keyword-only.

### Reciprocal Rank Fusion (RRF)

RRF merges results from multiple ranked lists without requiring score normalization. The formula:

```
RRF_score(artifact) = sum(1 / (k + rank_i)) for each ranked list i
```

Where `k=60` is the standard constant (Cormack et al., 2009). This handles the score distribution mismatch between keyword (BM25 scores) and vector (cosine similarities) without calibration.

### Contextual retrieval (Anthropic technique)

Before embedding, each artifact's summary is prepended to its content. This is Anthropic's contextual retrieval technique: by including document-level context alongside the chunk content, the embedding captures semantic meaning at both granularities. This yields ~49% retrieval improvement with zero additional LLM calls and no API dependency (embeddings are generated locally via `all-MiniLM-L6-v2`).

### Reranking

The top results from RRF can be optionally re-scored with full cosine similarity on the original (non-truncated) embeddings. This is more expensive but produces higher-quality final rankings. Results without embeddings keep their RRF score with a slight penalty so embedding-based results rank higher when scores are close.

### Fallback chain

```
1. Both keyword + vector available → RRF fusion → rerank → results
2. Only keyword available → keyword results with RRF scoring → results
3. Only vector available → vector results with RRF scoring → results
4. Neither available → empty results
```

Vector search failure (e.g., model not loaded, dimension mismatch) is caught and falls back silently to keyword-only. No search query ever throws an exception.

---

## Recall

When the AI needs the full content of a compressed/encrypted artifact:

```
engram recall ~/.claude/projects/.../session-2025-06.jsonl
  │
  ├─ Step 1: Registry lookup
  │   Look up in artifact-registry.json:
  │     tier: cold
  │     compressed_path: session-2025-06.jsonl.cold.zst.encf
  │     encrypted: true
  │     sha256: 92d54fa6...
  │
  ├─ Step 2: Decrypt (if encrypted)
  │   Python sends "DECRYPT <path> <output> cold" to engram-vault
  │   Rust sidecar:
  │     → Retrieves cold private key from macOS Keychain
  │     → Touch ID prompt on Apple Silicon
  │     → Key held in Zeroizing<T> wrapper in mlock'd memory (not swappable)
  │     → In-process ML-KEM-768 + X25519 decapsulation → HKDF-SHA256 → AES-256-GCM
  │     → Zeroizing<T> drop fires on all exit paths (normal, error, panic)
  │     → Decrypted .zst file returned
  │   Python receives: "OK"
  │   Python never saw the private key.
  │
  ├─ Step 3: Decompress
  │   Pipeline reversal based on tier:
  │     Cold: zstd decompress using trained dictionary
  │           → restore boilerplate references from store
  │           (BOILERPLATE_REF:a3f7b2e1 → full system prompt)
  │     Frozen: Parquet → JSONL conversion
  │             → restore boilerplate references
  │
  ├─ Step 4: Integrity check
  │   SHA-256 of decompressed content compared against stored hash
  │   Mismatch → abort + warning (file was tampered or corrupted)
  │   Match → proceed
  │
  ├─ Step 5: Restore to hot tier
  │   File written back to original location
  │   Metadata updated: tier=hot, last_accessed=now
  │   Embedding restored to full 384d float32 in hot HNSW graph
  │
  └─ AI reads the file normally
     On next engram run, it'll re-tier based on age + idle time
```

Retrieval times: warm ~10ms, cold ~500ms, frozen ~5 seconds. Add ~1-2 seconds for Touch ID prompt if encrypted.

---

## Encryption

### What Gets Encrypted

When encryption is enabled, **everything** is encrypted:

| Component | Encrypted? | How |
|-----------|-----------|-----|
| Compressed artifacts (.zst) | Yes | In-process Rust crypto with tier's public key (ML-KEM-768 + X25519 hybrid KEM, AES-256-GCM) |
| Semantic index (keywords, summaries) | Yes | Bundled into `index.tar.encf` on lock |
| Embeddings (all .npy files) | Yes | Part of index bundle |
| HNSW graphs (all .bin files) | Yes | Part of index bundle |
| LSH hash tables (.npz) | Yes | Part of index bundle |
| PQ codebook (.npz) | Yes | Part of index bundle |
| Artifact registry (.json) | Yes | Part of index bundle |
| Boilerplate store (prompt fragments) | Yes | Bundled into `boilerplate.tar.encf` on lock |
| Audit log | Yes | Part of index bundle |
| Compression dictionary | Yes | Part of index bundle |
| Config file | No — contains public keys and key source identifiers (service/account names). Not secret but treat as sensitive metadata. | 0600 permissions |

### Index Encryption

The index is encrypted as a bundle at session end and decrypted at session start:

```
Session start:
  engram unlock (or any engram command auto-unlocks)
    → Rust sidecar decrypts index.tar.encf (Touch ID)
    → Extracts all index files to ~/.engram/ with 0600 permissions
    → Index loaded into memory, ready for search

During session:
  Index files exist as plaintext in ~/.engram/ (0700 directory)
  All search, context, and tier operations work normally

Session end:
  engram lock
    → Bundles all index files into index.tar
    → Rust sidecar encrypts to index.tar.encf
    → Deletes all plaintext index files
    → Deletes boilerplate store (encrypted separately)
    → Only encrypted .encf files remain on disk
```

When locked, an attacker with filesystem access sees only encrypted blobs. No keywords, no summaries, no embeddings, no file paths, no session metadata.

### .encf v2 File Format

All encrypted files use the `.encf` v2 binary format (no external tools required):

```
Offset  Size     Field
0       4        ENCF magic bytes
4       1        Version (2)
5       2        KEM ciphertext length (little-endian)
7       1088     ML-KEM-768 ciphertext
1095    32       X25519 ephemeral public key
1127    16       HKDF-SHA256 salt
1143    12       AES-256-GCM nonce
1155    8        Plaintext length (little-endian)
1163    variable Ciphertext + 16-byte GCM authentication tag
```

Algorithms: ML-KEM-768 (FIPS 203) + X25519 hybrid KEM for key encapsulation, HKDF-SHA256 (SP 800-56C) for key derivation, AES-256-GCM (FIPS 197 + SP 800-38D) for authenticated encryption.

---

## Rust Crypto Sidecar

`engram-vault` is a compiled Rust binary that handles all cryptographic operations in-process. No external binaries (no `age`, no `openssl`). All crypto is performed using Rust crates directly.

### Why Rust, not Python

Python cannot securely handle private keys:
- Strings are immutable — can't be zeroed
- Garbage collector decides when memory is freed
- No `mlock` — key material can be swapped to disk
- No `mprotect` — any same-UID process can read `/proc/<pid>/mem`

### What the sidecar does

```
Python sends:   DECRYPT <input> <output> <tier>
Sidecar:        1. Reads private key from macOS Keychain (Security.framework)
                   (pub(crate) visibility on all keychain functions for defense-in-depth)
                   (tier validation inside keychain functions, redundant with main.rs)
                   (set-first-then-delete-retry pattern to avoid destroying keys on failed writes)
                2. Key held in Zeroizing<T> wrapper in mlock'd memory (not swappable)
                3. In-process ML-KEM-768 + X25519 decapsulation
                4. HKDF-SHA256 key derivation (ikm in Zeroizing<T>)
                5. AES-256-GCM decryption (aes_key in Zeroizing<T>)
                6. Zeroizing<T> drop fires on ALL exit paths — normal, error, and panic
                7. Core dumps disabled (setrlimit RLIMIT_CORE=0)
                8. Path traversal prevention: validate_path rejects ".." sequences
                9. File size limit: 256 MB max to prevent mlock exhaustion
Python receives: OK
```

The private key never: enters Python, touches disk, appears in process arguments, hits swap, survives a crash dump. No external process is spawned — all crypto is in-process.

### Protocol

```
ENCRYPT <input> <output> <tier>  → OK | ERROR <msg>
DECRYPT <input> <output> <tier>  → OK | ERROR <msg>
KEYGEN <tier>                     → OK <pubkey> | ERROR <msg>
PING                              → PONG
QUIT                              → BYE
```

Input validation: paths with newlines or null bytes are rejected (prevents command injection via the line protocol). Tier names validated against allowlist.

---

## Key Management

### Simple mode (one key for all tiers)

```json
{
  "encryption": {
    "enabled": true,
    "envelope_mode": false,
    "recipient_pubkey": "age1..."
  }
}
```

One public key encrypts everything. Decryption uses a single identity.

### Envelope mode (per-tier keypairs, per-artifact DEKs)

```json
{
  "encryption": {
    "enabled": true,
    "envelope_mode": true,
    "warm_pubkey": "age1...",
    "cold_pubkey": "age1...",
    "frozen_pubkey": "age1...",
    "warm_private_source": "keychain:engram:warm-key",
    "cold_private_source": "keychain:engram:cold-key",
    "frozen_private_source": "keychain:engram:frozen-key"
  }
}
```

Each tier has independent keypairs. Each artifact gets a unique 256-bit DEK. Compromise one tier, others stay safe. Key rotation re-wraps DEK headers in O(metadata), not O(data).

### Key sources (where private keys live)

| Source | Format | Security Level |
|--------|--------|---------------|
| macOS Keychain + Touch ID | `keychain:engram:warm-key` | Hardware-bound on Apple Silicon |
| HashiCorp Vault | `command:vault kv get ...` | Enterprise-grade |
| Cloud KMS | `command:aws secretsmanager ...` | Cloud-managed |
| Environment variable | `env:VAR_NAME` | CI/CD only |
| File on disk | Blocked | Deliberately disabled |

---

## Audit Logging

Disabled by default. Enable with `"audit_log": true` in config.

### What's logged

```
1710720000 TIER hot>warm 9.4x abc7f2
1710720001 TIER warm>cold 11.2x d4e891
1710730000 RECALL cold abc7f2
1710730001 DECRYPT warm abc7f2 ok
1710740000 SEARCH 5hits
1710750000 ROTATE warm gen1>gen2 37headers
```

Timestamp, operation, tier, 6-char artifact hash, outcome. That's it.

### What's NOT logged

File paths, filenames, key sources, query strings, content, keywords, summaries, usernames, private keys.

### PII/Secret detection

Every log line passes through regex-based detection before writing. If a line matches any pattern, it's replaced with `REDACTED`:

- `AGE-SECRET-KEY-*` — legacy age private keys
- `age1*` — legacy age public keys
- `-----BEGIN * KEY-----` — PEM keys
- `ssh-(rsa|ed25519) *` — SSH keys
- `AKIA*` — AWS access keys
- `sk-*` — API keys
- `ghp_*` — GitHub tokens
- `*@*.*` — Email addresses
- `/Users/*/` — macOS home paths
- `/home/*/` — Linux home paths
- `password|secret|token|credential` — Secret keywords

### Size cap

10 MB maximum. After 10 MB, writes are silently dropped. User must rotate.

### Encrypted at rest

When `engram lock` runs, the audit log is included in the encrypted index bundle. Only encrypted .encf files remain on disk.

---

## Lookup Tables

The architecture is nested lookup tables all the way down. Every retrieval step uses precomputed data instead of recomputation — the same principle DeepSeek uses when they absorb projection matrices into precomputed operations, and MemoryFormer uses when it replaces linear layers with hash table lookups.

| What's Stored Once | What It Replaces | Size | Speed |
|-------------------|-----------------|------|-------|
| Keyword inverted index | Scanning every file for a string | ~1 MB for 10K artifacts | O(1) per keyword |
| Compression dictionary | Relearning compression patterns per file | 112 KB (one-time training) | 2-5x faster compression |
| Boilerplate store | Storing 4,500 copies of the same prompt | 64 bytes per ref vs 5,000 tokens per copy | O(1) hash lookup |
| HNSW nearest-neighbor graph | Linear scan over all embeddings | ~10 MB for 10K artifacts | O(log n) vs O(n) |
| LSH hash tables | Full similarity computation | 4 tables × 4096 buckets | O(1) hash + bucket scan |
| PQ codebook | Storing full 3,072-byte embeddings | 8 bytes per artifact (384x reduction) | O(M) centroid lookups |
| Matryoshka truncation | Training separate embedding models per tier | Zero extra cost (truncate) | Same model, 4 resolutions |
| Binary packbits | Float32 cosine similarity on frozen tier | 8 bytes per artifact (vs 1,536) | Hamming via CPU popcount |

### Why this makes it efficient

Without lookup tables, every search would: scan every file on disk for a keyword match, decompress candidates to check content, and compute full cosine similarity over full-dimension embeddings. With the lookup table stack:

- **Keyword search drops from O(files × file_size) to O(1) per keyword.** The inverted index maps keywords to artifact IDs directly.
- **Vector search drops from O(n × 384) to O(log n).** HNSW navigates a graph instead of computing similarity against every embedding.
- **Frozen-tier search drops from cosine similarity (768 multiplications per pair) to Hamming distance (single popcount instruction).** Binary embeddings at 8 bytes are 192x smaller than float32 at 1,536 bytes.
- **Compression skips 40-70% of content** because the boilerplate store replaces repeated system prompts with hash references. The compressor never sees content that was already stored once.
- **The dictionary lets zstd skip schema learning.** Without a trained dictionary, zstd must rediscover that `"role":`, `"content":`, `"timestamp":` are common patterns in every file. With the dictionary, those patterns are precomputed byte codes.

The net effect: a search across 10,000 artifacts completes in under 50ms. A recall from frozen tier takes ~5 seconds. Without lookup tables, the same search would take seconds (full scan) and recall would require decompressing every candidate to check content.

---

## Embedding Architecture

Tiered embeddings follow the Matryoshka pattern — one model, four resolutions:

| Tier | Dimensions | Type | Size per Artifact | Search Method |
|------|-----------|------|-------------------|--------------|
| Hot | 384 | float32 | 1,536 bytes | Cosine similarity via HNSW |
| Warm | 256 | float32 | 1,024 bytes | Cosine similarity via HNSW |
| Cold | 128 | int8 | 128 bytes | Quantized cosine via HNSW |
| Frozen | 64 | binary | 8 bytes | Hamming distance via popcount |

Total index size for 10,000 artifacts across all tiers: ~10 MB (vs ~30 MB for full-resolution everywhere).

---

## File Permissions

| File/Directory | Permissions | Why |
|---------------|------------|-----|
| `~/.engram/` | 0700 | Only owner can access the directory |
| `config.json` | 0600 | Contains public keys and scan paths |
| `artifact-registry.json` | 0600 | Contains file hashes and paths |
| `semantic-index.json` | 0600 | Contains keywords and summaries |
| `audit.log` | 0600 | Contains operation timestamps |
| All `.npy`, `.bin`, `.npz` files | 0600 | Embedding and graph data |
| All temp files | 0600 | Created via `tempfile.mkstemp` with explicit chmod |
| Boilerplate store | 0700 | Directory containing plaintext prompt fragments |
| Compressed artifacts | 0600 | Written via `fileutil.atomic_write_bytes` |

---

## Threat Model

### Protects against

- Data at rest on stolen/lost/compromised devices
- "Harvest now, decrypt later" quantum attacks (ML-KEM-768)
- Unauthorized disk reads of AI session data
- Forensics on decommissioned hardware
- Index metadata leakage (when locked)
- Key material in Python memory, swap, core dumps, process args

### Does NOT protect against

- Compromised process with same-UID ptrace access
- Attacker with your Keychain password
- Trojanized `engram-vault` binary
- Root compromise on non-Secure-Enclave hardware
- Malicious AI assistant that exfiltrates data before compression
- Index metadata while unlocked during an active session

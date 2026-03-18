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
| SHA-256 hash | Integrity fingerprint | `artifact-registry.json` |
| Keyword extraction | Top 30 keywords by frequency | `semantic-index.json` |
| Summary generation | First heading + paragraph (md), field names + count (jsonl) | `semantic-index.json` |
| Embedding (if enabled) | 384-dim vector via all-MiniLM-L6-v2 | `embeddings-hot.npy` |
| HNSW insert | Nearest-neighbor graph entry | `hnsw-hot.bin` |
| LSH hash | Hash bucket assignment for O(1) lookup | `lsh-tables.npz` |
| Timestamps | Created, last accessed, last modified | `artifact-registry.json` |

Gzip-compressed files (`.jsonl.gz` from Claude) are decompressed in memory for indexing. The file on disk stays compressed.

---

## Tier Transitions

| Transition | Age Threshold | Idle Threshold | What Happens |
|-----------|--------------|----------------|-------------|
| Hot → Warm | 1 week | 3 days | Minify JSON → zstd-3 compress |
| Warm → Cold | 1 month | 2 weeks | Decompress warm → strip boilerplate → dict-trained zstd-9 |
| Cold → Frozen | 3 months | 1 month | Decompress cold → restore boilerplate → Parquet columnar + zstd-19 |

Both conditions (age AND idle) must be met. All thresholds configurable in `config.json`.

After compression, if encryption is enabled:
- The compressed file is encrypted with the tier's public key
- An `.envelope.json` header stores the per-artifact encrypted DEK (in envelope mode)
- The original/warm/cold file is deleted
- The embedding is truncated to the tier's Matryoshka dimension

---

## Compression Pipeline

Each tier applies different transformations. This is not just "higher zstd levels."

### Warm (4-5x)

```
Raw JSONL → strip whitespace (30-40% reduction) → zstd level 3
```

### Cold (8-12x)

```
Raw content → strip boilerplate (hash refs replace repeated system prompts)
            → minify JSON → compress with trained dictionary (zstd level 9)
```

The compression dictionary (`compression.dict`, 112 KB) is trained on your actual session logs. It encodes the shared schema (JSON keys, common tokens, tool call formats) as known byte patterns.

### Frozen (20-50x)

```
Raw JSONL → strip boilerplate → minify
          → transpose rows to columns (Parquet format)
          → per-column encoding:
              "role" column: run-length encoding (cardinality 2)
              "timestamp" column: delta encoding (monotonic ints)
              "content" column: dictionary encoding + zstd-19
```

---

## Search and Retrieval

Search never decompresses artifacts. It operates on the precomputed index. When embeddings are available (`pip install engram[embeddings]`), search uses hybrid retrieval (keyword + vector + reciprocal rank fusion). Without embeddings, it falls back to keyword-only.

```
Query: "authentication refactor"

Layer 1: KEYWORD LOOKUP — O(1) per keyword
  Inverted index: "authentication" → [art_42, art_891]

Layer 2: LSH HASH — O(1)
  Random hyperplane hash → bucket → candidate artifacts

Layer 3: HNSW GRAPH — O(log n) per tier
  Navigate nearest-neighbor graph at each tier's dimension:
    hot (384d) → warm (256d) → cold (128d) → frozen (64d binary)

Layer 4: RECIPROCAL RANK FUSION
  Merge keyword + vector results: RRF_score = Σ(1/(60+rank_i))

Layer 5: RERANK (optional)
  Top results re-scored with full cosine similarity
```

The AI sees summaries (10-20% of token cost). Full recall only on demand.

---

## Recall

When full content is needed:

1. Look up artifact in registry → find compressed path and tier
2. **Decrypt** (if encrypted) → Rust sidecar retrieves private key from Keychain, pipes to age via stdin, zeros key
3. **Decompress** → pipeline reversal (Parquet → JSONL, restore boilerplate, decompress zstd)
4. **Integrity check** → SHA-256 of decompressed content vs stored hash
5. **Restore to hot tier** → file written to original location, metadata updated, embedding restored to full 384d

Retrieval time: warm ~10ms, cold ~500ms, frozen ~5 seconds. Add ~1-2 seconds for Touch ID if encrypted.

---

## Encryption

### What Gets Encrypted

When encryption is enabled, **everything** is encrypted:

| Component | Encrypted? | How |
|-----------|-----------|-----|
| Compressed artifacts (.zst) | Yes | age with tier's public key (ML-KEM-768 hybrid) |
| Semantic index (keywords, summaries) | Yes | Bundled into `index.tar.age` on lock |
| Embeddings (all .npy files) | Yes | Part of index bundle |
| HNSW graphs (all .bin files) | Yes | Part of index bundle |
| LSH hash tables (.npz) | Yes | Part of index bundle |
| PQ codebook (.npz) | Yes | Part of index bundle |
| Artifact registry (.json) | Yes | Part of index bundle |
| Boilerplate store (prompt fragments) | Yes | Bundled into `boilerplate.tar.age` on lock |
| Audit log | Yes | Part of index bundle |
| Compression dictionary | Yes | Part of index bundle |
| Config file | No — contains only public keys (safe) | 0600 permissions |

### Index Encryption

The index is encrypted as a bundle at session end and decrypted at session start:

```
Session start:
  engram unlock (or any engram command auto-unlocks)
    → Rust sidecar decrypts index.tar.age (Touch ID)
    → Extracts all index files to ~/.engram/ with 0600 permissions
    → Index loaded into memory, ready for search

During session:
  Index files exist as plaintext in ~/.engram/ (0700 directory)
  All search, context, and tier operations work normally

Session end:
  engram lock
    → Bundles all index files into index.tar
    → Rust sidecar encrypts to index.tar.age
    → Deletes all plaintext index files
    → Deletes boilerplate store (encrypted separately)
    → Only encrypted .age files remain on disk
```

When locked, an attacker with filesystem access sees only encrypted blobs. No keywords, no summaries, no embeddings, no file paths, no session metadata.

---

## Rust Crypto Sidecar

`engram-vault` is a 364 KB compiled Rust binary that handles all private key operations.

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
                2. Key exists in mlock'd memory (not swappable)
                3. Pipes key to age via /dev/stdin (not argv, not disk)
                4. Zeros key via zeroize crate (deterministic, not GC)
                5. Core dumps disabled (setrlimit RLIMIT_CORE=0)
                6. Environment cleared (.env_clear() on age subprocess)
Python receives: OK
```

The private key never: enters Python, touches disk, appears in process arguments, hits swap, survives a crash dump.

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

- `AGE-SECRET-KEY-*` — age private keys
- `age1*` — age public keys
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

When `engram lock` runs, the audit log is included in the encrypted index bundle. Only encrypted .age files remain on disk.

---

## Lookup Tables

Every retrieval step uses precomputed lookup tables instead of recomputation:

| Lookup Table | What It Replaces | When Built |
|-------------|-----------------|------------|
| Keyword inverted index | Scanning every file for a string | Registration |
| Compression dictionary (112 KB) | Relearning compression patterns per file | Dictionary training (one-time) |
| Boilerplate store | Storing 4,500 copies of the same prompt | Cold tier transition |
| HNSW nearest-neighbor graph | Linear scan over all embeddings | Registration |
| LSH hash table (4 tables × 4096 buckets) | Full similarity computation | Registration |
| PQ codebook (8 sub-vectors × 256 centroids) | Storing full 3,072-byte embeddings | Codebook training (one-time) |
| Matryoshka truncation | Training separate models per tier | Built into the embedding model |
| Binary packbits | Float32 cosine similarity | Frozen tier transition |

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
- Trojanized `age` or `engram-vault` binary
- Root compromise on non-Secure-Enclave hardware
- Malicious AI assistant that exfiltrates data before compression
- Index metadata while unlocked during an active session

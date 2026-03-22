# Engram FAQ

## General

### What is Engram?
A tiered memory compression engine for AI assistants. It extends AI context windows by compressing, indexing, and encrypting old sessions — modeled on how the brain stores memory through progressive compression.

### Why not just use a bigger context window?
Context windows will grow to 10M tokens. That makes capacity less scarce, but it does NOT solve:
- **Finding the right context.** 10M tokens of everything is worse than 32K of the right thing. Search matters more as context grows.
- **Cost.** Loading 40MB into every API call is expensive. Compression reduces what needs to be loaded.
- **Integrity.** A bigger window doesn't tell you if recalled content is real. Merkle verification does.
- **Privacy.** More data per prompt = more sensitive data exposed. Tier-gated encryption limits what enters the context.

### How does it compare to just saving chat logs?
Raw logs grow forever and have no search, no compression, no integrity verification, and no encryption. Engram gives you 11x compression, keyword + semantic search, SHA3-256 Merkle integrity proofs on every result, and optional post-quantum encryption — all while keeping everything searchable without decompression.

---

### What is context drift?
The compounding approximation error when an LLM references compressed or summarized memory instead of original content. Each recall through a lossy representation introduces a small error. Over many references, these errors compound — the model builds confidently on a foundation that has drifted from the original.

Engram mitigates context drift two ways:
1. **Merkle integrity** — proves the recalled artifact is bit-for-bit identical to what was stored. The drift may happen in the summary, but the original is always recoverable and provably intact.
2. **Tiered recall** — summaries serve 80% of queries (fast, approximate). When precision matters, `engram recall` decompresses the original content. The original is the anchor that prevents drift from compounding indefinitely.

---

## The Four Tiers

### How do the tiers work?

| Tier | Age | Compression | Retrieval | Brain Analogy |
|------|-----|-------------|-----------|---------------|
| **Hot** | Now | 1x (uncompressed) | Instant | Working memory (prefrontal cortex) |
| **Warm** | 1 week | 4-5x (zstd-3) | ~10ms | Recent memory (hippocampus) |
| **Cold** | 1 month | 8-12x (zstd-9 + stripping) | ~200ms | Long-term memory (neocortex) |
| **Frozen** | 3+ months | 20-50x (Parquet columnar) | ~2s | Deep archive (tip-of-tongue) |

Each tier trades retrieval speed for storage efficiency. Artifacts move down automatically based on age and access patterns. Recalled artifacts promote back to hot.

### What triggers a tier transition?
Age and idle time. Default thresholds: hot → warm at 48 hours idle, warm → cold at 7 days, cold → frozen at 90 days. All configurable in `~/.engram/config.json`.

### Can I prevent an artifact from moving to a lower tier?
Frequently accessed artifacts resist demotion — accessing an artifact resets its idle timer. If you recall a cold artifact, it promotes back to hot.

---

## Merkle Tree Integrity

### What is a Merkle tree?
A binary tree where every leaf contains a hash of some data, and every internal node contains a hash of its two children. The root hash — a single 32-byte value — covers the entire tree. Change any leaf and every hash up to the root changes.

```
              Root: 061e...
             /            \
       Hash AB              Hash CD
      /      \             /      \
  Hash A    Hash B    Hash C    Hash D
    |         |         |         |
Session 1  Session 2  Session 3  Session 4
```

### How does it prevent hallucination?
When the AI claims "we discussed X in Session 3," Engram produces a Merkle proof — the path of hashes from Session 3's leaf to the root. If the proof verifies, the session is real. If not, the AI is making it up. Cryptographic proof, not trust.

### What is a Merkle proof?
A log(n)-sized path from a leaf to the root. To prove Session 3 exists in a tree of 1,000 sessions, you need only ~10 hashes (the proof path), not all 1,000 session hashes. You prove the session is authentic without revealing any other sessions.

### Why SHA3-256 instead of SHA-256?
Most Merkle trees (Bitcoin, Certificate Transparency) use SHA-256. Engram uses SHA3-256 for three reasons:

1. **Post-quantum collision resistance.** SHA-256's collision resistance drops to ~64-bit against quantum attacks (Brassard-Hoyer-Tapp). SHA3-256 maintains 128-bit. For Merkle proofs used in selective disclosure, collision resistance is the critical property.
2. **Sponge construction.** SHA-256 uses Merkle-Damgard, which is vulnerable to length extension attacks. SHA3's sponge construction is immune by design.
3. **Long-term audit trails.** Medical device compliance logs have 10-30 year retention. Choosing the stronger hash now costs nothing. Upgrading later requires re-hashing everything.

### What is root sealing?
The Merkle root proves no data was tampered with (integrity). The HMAC-SHA3-256 seal proves WHO computed it (authentication). The seal key is derived via HKDF from ML-KEM-768 key material inside the Rust sidecar — it never leaves the process.

Integrity without authentication means an attacker can build a valid tree with fake data. Authentication without integrity means the key holder could tamper with individual artifacts. You need both.

---

## Matryoshka Embeddings

### What are they?
Named after Russian nesting dolls. A single embedding vector where truncating to fewer dimensions produces a valid lower-dimensional embedding:

```
Hot:    384 dims (1536 bytes) — full fidelity semantic search
Warm:   256 dims (1024 bytes) — 33% smaller, minimal quality loss
Cold:   128 dims  (512 bytes) — 75% smaller, fast approximate search
Frozen:  64 dims  (256 bytes) — 94% smaller, Hamming distance
```

You don't retrain a model per tier. You generate one 384-dim embedding and truncate it. The all-MiniLM-L6-v2 model natively supports this.

### How does tiered search work?
Start at the cheapest tier (64-dim frozen, Hamming distance). Find rough candidates. Load 128-dim embeddings for the top 50 candidates. Rerank with full 384-dim for the top 10. You search 100,000 artifacts for the cost of searching 10.

### How expensive is embedding generation?
~225ms per session (one-time at registration). After that, search is a dot product — microseconds. Embedding generation happens once. Search happens thousands of times.

---

## The Rust Sidecar

### Why a separate Rust binary?
Four reasons, all security:

1. **Memory safety.** Rust prevents buffer overflows, use-after-free, and data races at compile time. The Merkle tree, HMAC seal, and all encryption run in compiled code, not interpreted Python.

2. **Process isolation.** If the Python process is compromised (malicious dependency, pickle exploit, prompt injection), the attacker can't reach the sidecar. They'd have to compromise a compiled binary — much harder.

3. **Key protection.** `mlockall` prevents key material from being swapped to disk. Core dumps are disabled. Keys exist in mlocked Rust memory, used for crypto operations, then zero-filled via `Zeroizing<T>`. They never touch Python's address space.

4. **Constant-time operations.** Merkle proof verification uses constant-time byte comparison (`ct_eq`). Timing side channels that could leak proof information are eliminated at the hardware level.

### How does Python talk to the sidecar?
stdin/stdout line protocol. Python starts the sidecar as a subprocess, sends commands (`PING`, `INDEX_SEARCH auth`, `MERKLE_PROOF 42`), reads responses (`PONG`, `OK [...]`, `OK <proof>`). One command per line. The sidecar stays alive for the session.

### What commands does it support?

| Command | Purpose |
|---------|---------|
| `ENCRYPT / DECRYPT` | AES-256-GCM file encryption via ML-KEM-768 |
| `KEYGEN` | Generate PQC keypair, store in Keychain |
| `MERKLE_ADD` | Add a hash to the Merkle tree |
| `MERKLE_ROOT / PROOF / VERIFY` | Tree operations |
| `MERKLE_SEAL / VERIFY_SEAL` | HMAC-SHA3 root authentication |
| `INDEX_ADD` | Add artifact with summary + keywords to the search index |
| `INDEX_SEARCH` | Keyword search with relevance scoring |
| `INDEX_LOOKUP` | Direct hash lookup (O(1)) |
| `INDEX_STATS` | Artifact count, keyword count, seal status |

### How big is the binary?
491 KB. Includes ML-KEM-768, X25519, AES-256-GCM, HKDF, SHA3-256, HMAC, Merkle tree, inverted keyword index, and the full protocol handler. Compiled with LTO and strip.

---

## Encryption

### What algorithms does Engram use?

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Key encapsulation | ML-KEM-768 + X25519 hybrid | NIST FIPS 203 |
| Data encryption | AES-256-GCM | NIST FIPS 197 + SP 800-38D |
| Key derivation | HKDF-SHA256 | NIST SP 800-56C |
| Merkle hashing | SHA3-256 | NIST FIPS 202 |
| Root sealing | HMAC-SHA3-256 | NIST FIPS 198-1 |
| Key storage | macOS Keychain | Apple Security.framework |

### What is ML-KEM-768?
NIST's post-quantum key encapsulation mechanism (FIPS 203, finalized 2024). It protects encrypted data against future quantum computers that could break RSA and ECC. Engram uses a hybrid scheme: ML-KEM-768 (quantum-safe) + X25519 (classical). Both shared secrets are combined via HKDF to derive the AES key. Even if one scheme is broken, the other still protects the data.

### Why post-quantum? Nobody has a quantum computer.
Correct. But Engram stores data that may need to be secure for years. The "harvest now, decrypt later" threat: an adversary records your encrypted data today and decrypts it when quantum computers arrive. ML-KEM-768 eliminates this threat at zero performance cost (key encapsulation adds <1ms).

### Are summaries encrypted?
No. Summaries and keywords are stored unencrypted because they must be searchable. This is a deliberate tradeoff: summaries reveal what a session was ABOUT but not what was SAID. The full content stays encrypted on disk. The Merkle proof proves the summary matches the encrypted content without decrypting it.

For deployments where even summaries must be hidden: encrypted search (searchable symmetric encryption) is a future option, at the cost of orders-of-magnitude slower search.

### Where are encryption keys stored?
macOS Keychain, accessed via Security.framework from the Rust sidecar. Keys are protected by Touch ID / Face ID. The sidecar retrieves keys from Keychain into mlocked memory, performs the crypto operation, then zero-fills the key. Keys never enter Python, never touch disk outside Keychain, and never appear in process arguments or environment variables.

---

## Components

### How is Engram structured?

```
engram/
├── src/                          # Python: orchestration, CLI, search
│   ├── engine.py                 # Tiering engine (scan, compress, recall)
│   ├── pipeline.py               # Compression pipeline (zstd, Parquet)
│   ├── context.py                # Semantic index + context builder
│   ├── session_parser.py         # Claude Code session content extraction
│   ├── embeddings.py             # Matryoshka embedding generation
│   ├── vector_index.py           # HNSW approximate nearest neighbor
│   ├── hybrid_search.py          # RRF keyword + vector fusion
│   ├── lookup_tables.py          # LSH + Product Quantization
│   ├── metadata.py               # Artifact registry
│   ├── vault.py                  # Rust sidecar client
│   ├── spatial.py                # Spatial memory extension (Spot)
│   ├── encryption.py             # Encryption orchestration
│   ├── envelope.py               # Per-artifact envelope encryption
│   ├── audit.py                  # Audit logging
│   └── cli.py                    # Command-line interface
│
├── sidecar/                      # Rust: crypto + integrity + search index
│   └── src/
│       ├── main.rs               # Protocol handler (stdin/stdout)
│       ├── merkle.rs             # SHA3-256 Merkle tree + inverted keyword index
│       ├── crypto.rs             # ML-KEM-768 + X25519 + AES-256-GCM
│       └── keychain.rs           # macOS Keychain integration
│
└── tests/                        # 141 tests
    ├── test_merkle.py            # Merkle tree via sidecar
    ├── test_spatial.py           # Spatial memory
    ├── benchmark_retrieval.py    # Retrieval quality evaluation
    └── ...                       # Engine, pipeline, encryption, context tests
```

### What does Python do vs what does Rust do?

| Python | Rust Sidecar |
|--------|-------------|
| CLI interface | Encryption / decryption |
| Session file parsing | Key management (Keychain) |
| Compression orchestration | Merkle tree operations |
| Embedding generation | HMAC root sealing |
| Tier policy enforcement | Keyword search index |
| Context window management | Constant-time proof verification |

Rule: **Python orchestrates. Rust secures.** If it touches keys, hashes, proofs, or encrypted data, it runs in Rust.

---

## Performance

### Measured benchmarks (4,560 real artifacts)

| Operation | v1 (Python) | v2 (Rust sidecar) | Improvement |
|---|---|---|---|
| Direct lookup by hash | ~60ms | 0.04ms | **1,500x** |
| Search (few matches) | ~60ms | 0.5ms | **120x** |
| Search (many matches) | ~60ms | 5-20ms | **3-12x** |
| Compression ratio | — | 11.63x | — |
| Binary size | — | 491 KB | — |
| Test count | — | 141 passing | — |

The v1 bottleneck was parsing 8MB of JSON on every invocation. v2 loads the index into the sidecar once at session start and serves all queries from memory.

---

## Security

### What are the known risks?

| Risk | Mitigation | Status |
|------|-----------|--------|
| JSON index poisoning before load | Manifest signing (SHA3-256 + HMAC) | Designed, not yet enforced |
| Sidecar memory dump exposes summaries | mlockall prevents swap; accept for single-user | Accepted |
| Timing side channels on proof verify | Constant-time comparison in Rust | Implemented |
| Command injection via key source | Allowlist of permitted executables | Implemented |
| Non-atomic writes corrupt index | atomic_write_text for all persistence | Implemented |
| Concurrent access race conditions | File locking for metadata writes | Planned (v2 Phase 1) |

### Has it been security reviewed?
Yes. Two reviews:
1. **10-round security audit** (v1.0.1, 2026-03-19): 22 findings, 6 patches applied.
2. **5-domain architecture review** (v2, 2026-03-21): Applied cryptographer, data security, systems engineer, compliance specialist, red teamer. 5 HIGH findings fixed, 6 MEDIUM addressed.

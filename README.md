# Engram

**Brain-modeled tiered memory for AI — with post-quantum encryption and Merkle integrity.**

### The Problem

AI assistants forget. Context windows have hard limits. Fill it up and the oldest context falls off. Your assistant loses decisions from last week, code reviews from last month, and architecture conversations from last quarter. You re-explain the same context every session.

The standard solution is "just expand the context window." But larger windows don't solve finding the right context (10M tokens of everything is worse than 32K of the right thing), don't solve cost (loading gigabytes per API call is expensive), and don't solve security (more data per prompt = more data at risk).

### The Approach

This started as a hardware constraint problem. Limited disk, limited context window, months of AI session data piling up. The question was: how do you keep months of AI memory accessible without unlimited storage?

The answer came from neuroscience.

Your brain doesn't hold everything in working memory. It uses a tiered architecture: the **prefrontal cortex** holds ~7 items for immediate access. The **hippocampus** consolidates recent experiences into longer-term storage. The **neocortex** stores long-term memories distributed across regions, reconstructed from fragments when the right cue triggers recall. And the deepest memories take real effort to surface — the tip-of-tongue phenomenon.

Each tier trades retrieval speed for storage efficiency. That's not a limitation. It's what lets the system scale across decades. Engram applies this same architecture to AI memory.

```
HOT (now)    ████████████████████████████████████████  1,500 KB   1x    instant
WARM (1w)    ████████████                              340 KB   4-5x    ~10ms
COLD (1mo)   ██████                                    150 KB   8-12x   ~200ms
FROZEN (3mo) ██                                        50 KB   20-50x   ~2s
```

### Three Problems Solved

**Context persistence.** Old sessions compress into searchable tiers instead of being dropped. Months of decisions, code reviews, and conversations stay accessible through the semantic index. No re-explaining.

**Hardware constraints.** Six months of daily sessions would consume gigabytes uncompressed. Engram's multi-stage pipeline (4-5x warm, 8-12x cold, 20-50x frozen) shrinks that footprint by 90%+ while keeping everything searchable. Smarter storage, not more storage.

**Security of AI memory.** This is the problem nobody is solving yet. Every session you've ever had with an AI — stored in plaintext on disk. As personal AI assistants become persistent (remembering your preferences, your codebase, your decisions), that memory becomes a high-value target. An adversary who accesses your AI memory gets your entire professional history.

Engram adds post-quantum encryption (ML-KEM-768 + X25519 hybrid, NIST FIPS 203) so your AI memory is protected against both current and future threats. The "harvest now, decrypt later" (HNDL) risk — where an adversary records encrypted data today and breaks it with a quantum computer in 10-20 years — is real for long-lived data. AI memory that persists for years needs encryption that persists for decades. Per-artifact keys. Per-tier keypairs. Private keys handled by a compiled Rust sidecar that never lets them enter Python's address space.

Every recalled artifact is verified via a SHA3-256 Merkle tree with HMAC root sealing — proving the memory hasn't been tampered with and that the AI isn't hallucinating past conversations. Integrity and confidentiality, not just one or the other.

AI is here to stay. Secure memory for AI is the next big infrastructure problem. Engram is a first step.

No additional setup needed to expand memory. Run `engram init` (auto-detects your AI assistants), then `engram run` (compresses and indexes everything). Your AI immediately has access to months of context through the semantic index. The context window didn't get bigger. The memory behind it got smarter.

```
HOT (now)    ████████████████████████████████████████  1,500 KB   1x    instant
WARM (1w)    ████████████                              340 KB   4-5x    ~10ms
COLD (1mo)   ██████                                    150 KB   8-12x   ~500ms
FROZEN (3mo) ██                                        50 KB   20-50x   ~5s
```

### Merkle Tree Integrity — Anti-Hallucination for AI Memory

*Added 2026-03-21. SHA-256 replaced entirely with SHA3-256. HMAC-SHA3 root sealing added. Python implementation archived — all Merkle operations moved to Rust sidecar.*

*Two separate protections: SHA3-256 Merkle tree proves data hasn't been tampered with (integrity). HMAC seal proves who computed it (authentication). Integrity without authentication means an attacker can build a valid tree with fake data. Authentication without integrity means the key holder could tamper with artifacts. You need both. Neither replaces Engram's existing encryption (ML-KEM-768 + AES-256-GCM) — encryption hides content, Merkle proves content is real. Separate threats, separate systems.*

AI systems hallucinate. They fabricate citations, invent past conversations, and confidently reference decisions that never happened. When your AI says "we decided X last week," how do you know that conversation actually existed?

Engram's Merkle tree proves it.

Every artifact registered in Engram gets a leaf in a binary hash tree. The root hash is a single value that covers every artifact across all four tiers. If any artifact is tampered with, corrupted, or fabricated, the root hash changes.

```
                  Root: 061e... (SHA3-256)
                  Seal: 145f... (HMAC-SHA3, PQC-derived key)
                    /              \
             Hash AB                Hash CD
            /      \               /      \
      Hash A      Hash B     Hash C      Hash D
        |           |          |           |
   Session 1   Session 2   Session 3   Session 4
    (hot)       (warm)      (cold)     (frozen)
```

**Anti-hallucination:** When the AI claims "we discussed this in Session 3," Engram can produce a Merkle proof — a path of hashes from Session 3's leaf to the root. If the proof verifies, the conversation is real. If it doesn't, the AI is hallucinating. Cryptographic proof, not trust.

**Selective disclosure:** To prove Session 3 exists, you only need 3 hashes (the proof path), not the contents of Sessions 1, 2, or 4. You prove the memory is real without revealing anything else.

**Tamper detection:** Run `engram verify`. One root hash check tells you every artifact across all four tiers is intact. No need to decompress cold or frozen files. O(log n) instead of O(n).

```bash
$ engram verify
Integrity Verification
========================================
Total checked:  487
  Passed:       482
  Failed:       0
  Skipped:      5  (no hash stored)

Merkle Tree
  Root:         061e4093b1a0...
  Leaves:       482
  Integrity:    PASS
```

**How it works with the tiers:**

| Tier | Merkle Behavior |
|------|----------------|
| **Hot** | Leaf added on `engram scan`. Hash = SHA3-256 of original content. |
| **Warm** | Leaf preserved. Hash stays valid — compression is lossless at this tier. |
| **Cold** | Leaf preserved. Hash of pre-compression content remains verifiable via proof. |
| **Frozen** | Leaf preserved. Months-old artifacts verifiable without decompressing Parquet. |

#### Why SHA3-256 Instead of SHA-256

Most Merkle tree implementations use SHA-256. Bitcoin established it as the default in 2009, and RFC 6962 (Certificate Transparency) codified it in 2013. But SHA-256 is a convention, not a requirement. Any collision-resistant hash function works.

Engram uses SHA3-256 (NIST FIPS 202) for three reasons:

1. **Post-quantum collision resistance.** SHA-256 has ~128-bit collision resistance classically, but quantum algorithms (Brassard-Hoyer-Tapp) reduce this to ~64-bit. SHA3-256 maintains 128-bit collision resistance even against quantum adversaries. For Merkle proofs used in selective disclosure (proving one artifact exists without revealing others), collision resistance is the property that matters.

2. **Sponge construction.** SHA-256 uses Merkle-Damgard construction, which is susceptible to length extension attacks. SHA3's sponge construction is immune by design. While length extension isn't a direct Merkle tree vulnerability, using a hash with fewer structural weaknesses reduces the attack surface.

3. **Long-term audit trails.** Engram's Merkle tree targets use cases with 10-30 year retention requirements — medical device compliance logs (FDA), regulatory audit records (NIST AI RMF), BCI session integrity (QIF). Choosing the stronger hash now costs nothing (SHA3-256 runs at comparable speed to SHA-256 in Rust with LTO). Upgrading later would require re-hashing every artifact in every tier.

The Merkle tree runs entirely in the Rust sidecar (`engram-vault`). SHA3-256 hashing, proof generation, proof verification, and HMAC root sealing all happen in compiled Rust with mlocked memory and zero core dumps. Python never handles hash computations for integrity-critical operations.

#### PQC Root Sealing

The Merkle root is sealed with HMAC-SHA3-256 using a key derived from the ML-KEM-768 (FIPS 203) shared secret via HKDF. This proves the root was computed by a process with access to the post-quantum key material — not just that the hashes are correct, but that the entity who computed them holds the PQC key.

```
ML-KEM-768 shared secret
    → HKDF-SHA3-256 key derivation
    → HMAC-SHA3-256(merkle_root)
    → root seal (32 bytes, constant-time verified)
```

Verification is constant-time in the Rust sidecar (prevents timing side-channel attacks on seal comparison).

The full PQC integrity stack:

| Layer | Algorithm | NIST Standard |
|-------|-----------|---------------|
| Tree hashes | SHA3-256 | FIPS 202 |
| Root seal | HMAC-SHA3-256 | FIPS 198-1 + FIPS 202 |
| Seal key source | ML-KEM-768 + HKDF | FIPS 203 + SP 800-56C |
| Artifact encryption | AES-256-GCM | FIPS 197 + SP 800-38D |
| Key encapsulation | ML-KEM-768 + X25519 | FIPS 203 |
| All operations | Rust sidecar | mlocked, zero core dumps |

### Least Privilege by Design

The tiered architecture isn't just compression. It's the principle of least privilege applied to AI context.

Traditional least privilege: a user only gets the permissions they need for the current task. Engram least privilege: the AI only gets the context fidelity it needs for the current task.

| Tier | Access Level | What the AI Sees | Analogy |
|------|-------------|-----------------|---------|
| **Hot** | Full access | Complete session content, every token | Root access — current working set |
| **Warm** | Summaries | Key decisions, outcomes, compressed context | Read access — recent history |
| **Cold** | Keywords only | Semantic index entries, topic references | Directory listing — you know it exists |
| **Frozen** | Explicit recall required | Nothing until `engram recall` is invoked | Locked vault — must request access |

The constraint is real: the context window is finite. The enforcement is real: compression removes detail until you explicitly ask for it back. Old context doesn't linger at full fidelity. It compresses, indexes, and locks down — the same way a well-run system revokes elevated permissions after the task is done.

This means a compromised or misbehaving AI session can't silently access months of full-fidelity conversation history. It gets summaries and keywords. Full recall requires an explicit action (`engram recall <path>`) that can be logged, rate-limited, or gated behind encryption. The blast radius of any single session is bounded by its tier.

Add post-quantum encryption and the tiers become actual access barriers: even with disk access, frozen artifacts are ML-KEM-768 encrypted with per-artifact keys managed by a Rust sidecar that never lets private keys enter Python's address space.

---

**[FAQ](docs/FAQ.md)** — Merkle trees, Matryoshka embeddings, the Rust sidecar, PQC encryption, component architecture, performance benchmarks, and security review findings.

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Compression Pipeline](#compression-pipeline)
- [Encryption](#encryption)
- [Supported AI Assistants](#supported-ai-assistants)
- [Architecture](#architecture)
- [Security](#security)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)
- [AI Disclosure](#ai-disclosure)
- [License](#license)

---

## Quick Start

```bash
pip install bci-engram                   # install from PyPI
pip install bci-engram[embeddings]       # with semantic search (recommended)
engram init                              # guided setup
engram run --dry-run                     # preview (safe, no changes)
engram run                               # compress + encrypt
engram search "authentication refactor"  # search all tiers
engram context --query "auth patterns"   # get context for your AI
engram recall <path>                     # decompress a cold artifact
engram status                            # tier distribution
```

### Enable encryption

```bash
cd engram/sidecar && cargo build --release        # build crypto sidecar
engram encrypt-setup                              # generate keys + store in Keychain
```

---

## How It Works

**Brain-inspired tiering.** Artifacts move through tiers based on age and idle time:

| Transition | When | Pipeline | Ratio |
|-----------|------|----------|-------|
| Hot → Warm | 1 week old + 3 days idle | Minify JSON → zstd-3 | 4-5x |
| Warm → Cold | 1 month old + 2 weeks idle | Strip boilerplate → dict-trained zstd-9 | 8-12x |
| Cold → Frozen | 3 months old + 1 month idle | Columnar Parquet + dict + zstd-19 | 20-50x |

All thresholds configurable. Choose 2-tier (simple) or 4-tier (full) during setup.

**Hybrid search.** Every artifact is indexed with keywords, embeddings, LSH hashes, and HNSW graph entries before compression. Search uses a 6-layer retrieval stack: keyword lookup, LSH hash tables, HNSW nearest-neighbor graphs, Reciprocal Rank Fusion (BM25 + vector), optional reranking, and summary output. The index (~1 MB keywords + ~10 MB embeddings for 10K artifacts) is always loaded, never compressed. Search across all tiers without decompressing anything. Summaries load at 10-20% of token cost. Full recall on demand.

**Everything local.** No data leaves your machine. No telemetry. No cloud dependency. Zero network calls. Embedding model (`all-MiniLM-L6-v2`, ~80 MB) runs entirely in-process on CPU — no external API, no cloud inference. HNSW and LSH indexes operate on these local embeddings. Without the embedding model, keyword search still works.

---

## Compression Pipeline

Not just "higher zstd levels" (that gets 3.2x to 3.8x). Each tier applies different data transformations:

- **Warm:** JSON minification strips 30-40% of whitespace before zstd-3
- **Cold:** Boilerplate stripping replaces repeated system prompts (2,000-5,000 tokens per session) with 64-byte hash refs. Dictionary trained on your session logs teaches zstd the shared schema. Only unique content gets compressed.
- **Frozen:** JSONL transposed to columnar Parquet. `role` column (cardinality 2) → run-length encoded to nothing. `timestamp` column (monotonic) → delta encoded to nothing. Only `content` carries entropy. ClickHouse achieves 170x on logs with this approach.

### Real results

```
4,564 artifacts | 2.6 GB raw | 11.62x ratio | 1.6 GB saved | 132K keywords indexed
```

---

## Encryption

Optional. Engram works without it — compression, indexing, and context enhancement all function with zero encryption.

When enabled, uses **ML-KEM-768** (NIST FIPS 203) in hybrid mode with X25519, using AES-256-GCM (NIST FIPS 197) for data encryption and HKDF-SHA256 (NIST SP 800-56C) for key derivation.

### Crypto sidecar (engram-vault)

Private keys are handled by a compiled **Rust binary** — not Python. Keys never enter Python's address space, never touch disk, never appear in process args, never hit swap.

| Protection | How |
|-----------|-----|
| Keys out of Python | Rust sidecar is the crypto boundary |
| Keys off disk | OS credential vault → mlock'd memory → in-process crypto → zeroed |
| Keys out of swap | `mlockall()` at startup |
| Keys out of core dumps | `setrlimit(RLIMIT_CORE, 0)` |
| Keys out of logs | Regex PII detector blocks secrets before writing |
| No env hijack | `.env_clear()` on all subprocess calls |
| Zeroize on all paths | `Zeroizing<T>` wrappers on all key material — errors, panics, normal exit |

### Key material lifecycle

Private keys are **never** stored as environment variables and **never** passed over any wire or socket.

| Step | What happens |
|------|-------------|
| **1. Storage** | Private keys live in your OS credential vault — macOS Keychain (encrypted by the OS, protected by login password/Touch ID), Windows Credential Manager (DPAPI-backed), or Linux `libsecret`/GNOME Keyring. The vault encrypts keys at rest using OS-level protections. |
| **2. Retrieval** | The Rust sidecar calls the OS credential API (Security.framework on macOS) to read the key directly into its own `mlock`'d memory. No intermediate files, no pipes, no env vars. |
| **3. Usage** | Key material stays in-process only. Used for ML-KEM-768 decapsulation + X25519 Diffie-Hellman + HKDF-SHA256 key derivation + AES-256-GCM encrypt/decrypt. All NIST-approved algorithms. |
| **4. Cleanup** | `Zeroizing<Vec<u8>>` wrappers (RustCrypto `zeroize` crate) ensure deterministic zeroing on ALL exit paths — normal return, error return, and panic. Compiler barriers prevent the optimizer from eliding the zeroing. This satisfies NIST SP 800-57 Part 1 Section 8.3 key destruction requirements. |
| **5. Never** | Touches disk. Enters Python. Appears in process args. Passes through env vars. Goes over any wire or socket. Gets logged. Hits swap (`mlockall`). Appears in core dumps (`RLIMIT_CORE=0`). |

The Python side only ever sees the **public key** (for encryption). The sidecar is the crypto boundary.

### Two modes

| | Simple | Envelope |
|---|---|---|
| Keys | One for all tiers | Per-tier keypairs |
| Per-artifact isolation | No | Yes — unique 256-bit DEK each |
| Compromise radius | All data | One tier or one artifact |
| Key rotation | Re-encrypt all (O(data)) | Re-wrap headers (O(metadata)) |

### Why post-quantum now

NIST [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) (draft, Nov 2024): RSA-2048/P-256 deprecated by 2030, disallowed by 2035. "Harvest now, decrypt later" is a real threat. Starting with classical crypto means migrating before 2030. Start with PQ and you're done.

---

## Supported AI Assistants

| Assistant | Auto-detected |
|-----------|--------------|
| Claude Code | 18 locations: sessions, subagents, memory, debug, plans, tasks |
| ChatGPT | Desktop app cache |
| Cursor | Conversation logs |
| GitHub Copilot | Configuration cache |
| OpenAI Codex | Custom config |
| OpenClaw | Custom config |
| Any AI tool | Add any directory to `config.json` |

---

## Architecture

For the full detailed walkthrough of how every component works — registration, tier transitions, compression pipeline, hybrid search retrieval stack, HNSW vector index, embedding architecture, recall flow, encryption lifecycle, lookup tables, and index encryption — see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

**KV cache reduction through lookup tables.** The same insight that makes DeepSeek-V2 fast applies here: don't recompute what you can store compressed and look up. Every retrieval path in Engram uses precomputed structures — inverted keyword indexes (O(1) per keyword), LSH hash tables (O(1) approximate nearest neighbor), HNSW graphs (O(log n) exact nearest neighbor), Product Quantization codebooks (192x embedding compression), and trained compression dictionaries. The net effect: 10,000-artifact search completes in under 50ms without decompressing a single file.

### File tree

```
engram/
├── .claude-plugin/
│   └── plugin.json                # Anthropic marketplace manifest
├── .github/workflows/
│   └── ci.yml                     # GitHub Actions (pytest on push)
├── sidecar/                       # Rust crypto sidecar (459 KB binary)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                # mlock, zeroize, core dump disabled, env cleared
│       ├── crypto.rs              # ML-KEM-768 + X25519 + AES-256-GCM (NIST-only)
│       └── keychain.rs            # macOS Security.framework integration
├── src/
│   ├── engine.py                  # Orchestrator (scan → index → tier → recall)
│   ├── pipeline.py                # Multi-stage compression (minify → strip → dict → Parquet)
│   ├── context.py                 # Semantic index + hybrid search (keyword + vector + RRF)
│   ├── embeddings.py              # Matryoshka tiered embeddings (384/256/128/64-binary)
│   ├── vector_index.py            # HNSW nearest-neighbor per tier
│   ├── hybrid_search.py           # Reciprocal rank fusion + contextual retrieval
│   ├── lookup_tables.py           # LSH hash tables + Product Quantization codebook
│   ├── envelope.py                # Asymmetric PQ envelope encryption (per-artifact DEK)
│   ├── vault.py                   # Python client for Rust sidecar
│   ├── index_crypto.py            # Index bundle encryption (lock/unlock)
│   ├── encryption.py              # age CLI integration + validation
│   ├── compressor.py              # zstd streaming compress/decompress
│   ├── config.py                  # Config schema + validation + sensitive dir blocklist
│   ├── metadata.py                # Artifact registry + SHA-256 integrity
│   ├── scanner.py                 # AI assistant artifact auto-detection (18 locations)
│   ├── setup.py                   # Guided/interactive/auto setup wizard
│   ├── audit.py                   # Audit logger with regex PII/secret detection
│   ├── fileutil.py                # Shared atomic writes, path containment, hashing
│   └── cli.py                     # CLI: init, scan, run, status, search, context, recall,
│                                  #       reindex, verify, lock, unlock, encrypt-setup
├── skills/engram/
│   └── SKILL.md                   # Claude Code skill (13 use case examples)
├── hooks/
│   └── hooks.json                 # SessionStart + PreCompact hooks
├── docs/
│   ├── ARCHITECTURE.md            # Detailed technical documentation (442 lines)
│   ├── KEY-STORAGE-GUIDE.md       # Key management guide
│   └── blog-post.md               # Launch blog post
├── tests/                         # 116 tests
│   ├── test_compressor.py
│   ├── test_engine.py
│   ├── test_envelope.py
│   ├── test_metadata.py
│   ├── test_pipeline.py
│   ├── test_embeddings.py
│   └── test_lookup_tables.py
├── marketplace.json               # Plugin distribution metadata
├── pyproject.toml                 # Package config (pip installable)
├── LICENSE                        # MIT
└── README.md
```

---

## Security

- 10 rounds of security review (red team, crypto, GRC, supply chain, OWASP, embedding injection, index encryption, lookup table integrity, hybrid search fuzzing)
- Rust crypto sidecar — keys never in Python
- PQ encryption (ML-KEM-768 + X25519 hybrid)
- Per-artifact DEKs in envelope mode
- Audit logging with regex PII/secret detection
- SHA-256 integrity verification (quantum-safe: Grover reduces to 128-bit equivalent, well above NIST minimum per SP 800-57)
- Symlink protection, path containment, sensitive directory blocklist
- Input validation (newlines/nulls rejected in protocol)
- Core dumps disabled, memory locked, environment cleared
- No `shell=True` anywhere
- Embedding model supply chain verification (SHA-256 checksum on load)

### Third-party model verification

Engram uses one third-party model for semantic search (optional):

| Property | Value |
|----------|-------|
| Model | `sentence-transformers/all-MiniLM-L6-v2` |
| License | Apache 2.0 |
| Size | 86.7 MB (model.safetensors) |
| Parameters | 22.7M |
| SHA-256 | `53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db` |
| Downloads | 207M+ (widely vetted) |
| Runs | 100% local, in-process, CPU. No API calls. |

The checksum is verified on every model load. If the cached weights don't match the expected hash, Engram refuses to load the model and logs a security error. This detects supply chain tampering via compromised HuggingFace cache, typosquatted packages, or modified downloads.

Without the embedding model, keyword search still works. The model is an optional dependency (`pip install engram[embeddings]`).

### Threat model

**Protects against:** data at rest on stolen devices, harvest-now-decrypt-later, unauthorized disk reads, forensics on decommissioned hardware.

**Does NOT protect against:** compromised process with same-UID ptrace, attacker with your Keychain password, trojanized `engram-vault` binary, root compromise on non-Secure-Enclave hardware.

### Recommendations

See the full [security recommendations](#security-recommendations) section for the 10-point hardening guide (shared server isolation, cron lockdown, key compromise response, secure uninstall, etc.).

---

## Use Cases

**Solo dev:** 6 months of sessions → compressed from 200 MB to 15 MB. Search past decisions without re-explaining.

**Security researcher:** Sessions contain exploits and disclosure timelines. PQ envelope encryption. Touch ID on recall. Private keys in Keychain-backed Keychain.

**Team server:** Shared `~/.claude/`. Per-user encryption keys. Semantic index lets everyone search. Content isolation via per-tier keypairs.

**Multi-project:** Point Engram at 5 project memory dirs. Cross-project search finds the answer regardless of which project it was in.

**Spatial memory (Spot):** Engram extends beyond AI context to spatial data — LiDAR geometry, walking routes, indoor maps, bench/bathroom locations. The same tiered compression that handles conversation history handles spatial memory for [Spot](https://github.com/qinnovates/spot), a LiDAR navigation app. Routes compress from hot (live LiDAR) to frozen (Parquet-archived geometry). Peer-to-peer spatial sharing between devices uses NSP-wrapped payloads with Merkle proofs for selective verification. See [docs/SPATIAL-EXTENSION.md](docs/SPATIAL-EXTENSION.md).

---

## Configuration

All thresholds configurable in `~/.engram/config.json`:

```json
{
  "tier_policy": {
    "hot_to_warm_age_hours": 48,
    "warm_to_cold_age_hours": 336,
    "cold_to_frozen_age_hours": 2160
  },
  "encryption": {
    "enabled": true,
    "envelope_mode": true,
    "warm_pubkey": "<hex from KEYGEN>",
    "warm_private_source": "keychain:engram:warm-key"
  },
  "audit_log": false
}
```

Setup modes: `engram init` (guided), `--mode interactive` (pick locations), `--mode auto` (no prompts).

---

## CLI Reference

| Command | What |
|---------|------|
| `engram init` | Guided setup with tier choice and encryption |
| `engram scan` | Discover artifacts |
| `engram run` | Execute tier transitions |
| `engram run --dry-run` | Preview without changes |
| `engram status` | Tier distribution and stats |
| `engram search <query>` | Search across all tiers |
| `engram context --query <q>` | Budget-optimized context block |
| `engram recall <path>` | Decompress artifact to hot |
| `engram reindex` | Rebuild semantic index |
| `engram verify` | SHA-256 integrity check |
| `engram encrypt-setup` | Configure encryption |

---

## Requirements

```bash
pip install bci-engram                   # core (compression + indexing)
pip install bci-engram[embeddings]       # + semantic search (recommended)
```

- Python 3.10+
- `zstandard` >= 0.19.0 (auto-installed)
- `pyarrow` >= 14.0.0 (auto-installed, for frozen Parquet tier)
- `sentence-transformers` >= 2.2.0 (optional, for semantic search) — `pip install bci-engram[embeddings]`
- Rust toolchain (optional, to build the crypto sidecar) — `brew install rust` (macOS) or see [rustup.rs](https://rustup.rs)

---

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided as-is under the MIT license with no warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

**Data handling.** Engram compresses and optionally encrypts files on your local filesystem. Compression transformations (JSON minification, boilerplate stripping) are lossy for whitespace. Full semantic content is preserved and recoverable via `engram recall`, but byte-for-byte identity with the original file is not guaranteed after tiering.

**Encryption limitations.** If you lose your private key, encrypted data is unrecoverable. There is no backdoor, no recovery mechanism, no reset. The encryption is only as strong as your key management. The Rust crypto sidecar uses the ml-kem (v0.2, RustCrypto), aes-gcm (v0.10, RustCrypto), and x25519-dalek (v2) crates. These crates have not received a combined independent audit specific to this integration.

**Not a certified security product.** Engram has been reviewed through multiple rounds of automated security analysis but has not been formally audited by an independent security firm, is not FIPS-validated, and does not hold any compliance certifications. It is not a substitute for an HSM, a certified KMS, or a CMVP-validated crypto module.

**No liability for data loss.** The author is not responsible for data loss, corruption, unauthorized access, or any damages resulting from use of this software. Back up your data before enabling compression or encryption. Test `engram recall` before relying on it for critical data.

**Regulatory compliance is your responsibility.** Engram provides technical controls (encryption, audit logging, access separation) but does not constitute compliance with GDPR, HIPAA, SOC 2, PCI-DSS, or any other framework. Consult your compliance team.

---

## AI Disclosure

Built with AI assistance (Claude Opus 4.6, Anthropic). AI was used for code generation, security review, compression research, documentation, and test generation. All code reviewed by the author. All factual claims fact-checked against primary sources. The author takes full responsibility for all published content. Every git commit includes `Co-Authored-By` for transparency.

---

## License

MIT

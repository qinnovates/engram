# Engram

**Architecting Brain's Memory To Solve AI Context Persistence**

*A Semantic Indexing, KV Caching, and Lookup Tables approach for AI Memory.*

AI context windows have a hard limit. Fill it up and the oldest memories fall off. Your assistant forgets what you told it last week.

Engram solves this the way the brain does. Your brain doesn't hold everything in working memory. It tiers: recent experiences stay vivid (hot), recent days consolidate (warm), older memories compress into patterns (cold), deep memories take effort to surface (frozen). Each tier trades retrieval speed for storage efficiency.

This isn't a new idea in AI. DeepSeek-V2 ([arXiv:2405.04434](https://arxiv.org/abs/2405.04434)) applied the same principle to attention itself: instead of recalculating full key/value tensors for every token, they precompute and cache compressed latent vectors — reducing KV cache by 93.3% and achieving 5.76x throughput. Same insight: don't recompute what you can store compressed and recall on demand.

Engram applies this to your AI's *memory*. Four compression tiers, a searchable semantic index, and optional post-quantum encryption — so months of context fit in the same token budget that used to hold a few sessions. Save hardware resources at scale while protecting what matters.

```
HOT (now)    ████████████████████████████████████████  1,500 KB   1x    instant
WARM (1w)    ████████████                              340 KB   4-5x    ~10ms
COLD (1mo)   ██████                                    150 KB   8-12x   ~500ms
FROZEN (3mo) ██                                        50 KB   20-50x   ~5s
```

---

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
pip install engram
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
brew install age                                  # PQ encryption tool
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

**Semantic index.** Every artifact is keyword-indexed before compression. The index (~1 MB) is always loaded, never compressed. Search across all tiers without decompressing anything. Summaries load at 10-20% of token cost. Full recall on demand.

**Everything local.** No data leaves your machine. No telemetry. No cloud dependency. Zero network calls.

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

When enabled, uses **ML-KEM-768** (NIST FIPS 203, August 2024) in hybrid mode with X25519 via `age`. Same algorithm OpenSSH 10.0 made the default (April 2025).

### Crypto sidecar (engram-vault)

Private keys are handled by a compiled **Rust binary** — not Python. Keys never enter Python's address space, never touch disk, never appear in process args, never hit swap.

| Protection | How |
|-----------|-----|
| Keys out of Python | Rust sidecar is the crypto boundary |
| Keys off disk | Keychain → mlock'd memory → age stdin pipe |
| Keys out of swap | `mlockall()` at startup |
| Keys out of core dumps | `setrlimit(RLIMIT_CORE, 0)` |
| Keys out of logs | Regex PII detector blocks secrets before writing |
| No env hijack | `.env_clear()` on all subprocess calls |

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

For the full detailed walkthrough of how every component works — registration, tier transitions, compression pipeline, search retrieval stack, recall flow, encryption lifecycle, and lookup tables — see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

### File tree

```
engram/
├── .claude-plugin/
│   └── plugin.json                # Anthropic marketplace manifest
├── .github/workflows/
│   └── ci.yml                     # GitHub Actions (pytest on push)
├── sidecar/                       # Rust crypto sidecar (364 KB binary)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                # mlock, zeroize, core dump disabled, env cleared
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

- 7 rounds of security review (red team, crypto, GRC, supply chain, OWASP)
- Rust crypto sidecar — keys never in Python
- PQ encryption (ML-KEM-768 + X25519 hybrid)
- Per-artifact DEKs in envelope mode
- Audit logging with regex PII/secret detection
- SHA-256 integrity verification
- Symlink protection, path containment, sensitive directory blocklist
- Input validation (newlines/nulls rejected in protocol)
- Core dumps disabled, memory locked, environment cleared
- No `shell=True` anywhere

### Threat model

**Protects against:** data at rest on stolen devices, harvest-now-decrypt-later, unauthorized disk reads, forensics on decommissioned hardware.

**Does NOT protect against:** compromised process with same-UID ptrace, attacker with your Keychain password, trojanized `age` binary, root compromise on non-Secure-Enclave hardware.

### Recommendations

See the full [security recommendations](#security-recommendations) section for the 10-point hardening guide (shared server isolation, cron lockdown, key compromise response, secure uninstall, etc.).

---

## Use Cases

**Solo dev:** 6 months of sessions → compressed from 200 MB to 15 MB. Search past decisions without re-explaining.

**Security researcher:** Sessions contain exploits and disclosure timelines. PQ envelope encryption. Touch ID on recall. Private keys in Secure Enclave-backed Keychain.

**Team server:** Shared `~/.claude/`. Per-user encryption keys. Semantic index lets everyone search. Content isolation via per-tier keypairs.

**Multi-project:** Point Engram at 5 project memory dirs. Cross-project search finds the answer regardless of which project it was in.

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
    "warm_pubkey": "age1...",
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

- Python 3.10+
- `zstandard` >= 0.19.0 (auto-installed)
- `pyarrow` >= 14.0.0 (auto-installed, for frozen Parquet tier)
- `age` >= 1.3.0 (optional, for PQ encryption) — `brew install age`
- Rust toolchain (optional, to build the crypto sidecar) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

---

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided as-is under the MIT license with no warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

**Data handling.** Engram compresses and optionally encrypts files on your local filesystem. Compression transformations (JSON minification, boilerplate stripping) are lossy for whitespace. Full semantic content is preserved and recoverable via `engram recall`, but byte-for-byte identity with the original file is not guaranteed after tiering.

**Encryption limitations.** If you lose your private key, encrypted data is unrecoverable. There is no backdoor, no recovery mechanism, no reset. The encryption is only as strong as your key management. The `age` tool's PQ hybrid (ML-KEM-768) has not received a published independent audit specific to the post-quantum integration; the classical X25519 + ChaCha20-Poly1305 layer was audited by Cure53 (2019).

**Not a certified security product.** Engram has been reviewed through multiple rounds of automated security analysis but has not been formally audited by an independent security firm, is not FIPS-validated, and does not hold any compliance certifications. It is not a substitute for an HSM, a certified KMS, or a CMVP-validated crypto module.

**No liability for data loss.** The author is not responsible for data loss, corruption, unauthorized access, or any damages resulting from use of this software. Back up your data before enabling compression or encryption. Test `engram recall` before relying on it for critical data.

**Regulatory compliance is your responsibility.** Engram provides technical controls (encryption, audit logging, access separation) but does not constitute compliance with GDPR, HIPAA, SOC 2, PCI-DSS, or any other framework. Consult your compliance team.

---

## AI Disclosure

Built with AI assistance (Claude Opus 4.6, Anthropic). AI was used for code generation, security review, compression research, documentation, and test generation. All code reviewed by the author. All factual claims fact-checked against primary sources. The author takes full responsibility for all published content. Every git commit includes `Co-Authored-By` for transparency.

---

## License

MIT

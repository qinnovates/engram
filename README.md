# tiered-memory-engine

An AI-agnostic plugin that increases your assistant's effective context window through automatic tiered compression of memory artifacts, with optional post-quantum encryption.

Every AI assistant session generates artifacts: conversation logs, memory files, task caches, subagent outputs. These pile up fast. A 128K token context window fills in a few sessions. Older memories get dropped. Your assistant forgets things you told it last week.

tiered-memory-engine solves this the same way your brain does.

---

## How your brain does it — and how this plugin mirrors it

Your brain doesn't store yesterday's lunch and your childhood address the same way. It uses a tiered system where memories move through stages based on how recently and frequently you access them:

| Brain System | What It Does | Retrieval Speed | Plugin Equivalent |
|-------------|-------------|-----------------|-------------------|
| **Working memory** (prefrontal cortex) | Holds what you're thinking about right now. ~7 items. Active neural firing — not stored, just maintained. | ~40ms per item | **Hot tier** — uncompressed, instant access |
| **Recent memory** (hippocampus) | Consolidates today's experiences. The hippocampus acts as a temporary index, binding fragments together. During sleep, it replays memories into the neocortex for longer storage. | Hundreds of ms | **Warm tier** — lightly compressed (zstd-3), fast retrieval. Semantic index acts as the hippocampal pointer. |
| **Long-term memory** (neocortex) | Distributed storage across cortical regions. Reconstructed from fragments on recall, not read from a single address. Needs the right cue to trigger retrieval. | Seconds | **Cold tier** — heavily compressed (zstd-9), needs a search hit or explicit recall to decompress. |
| **Deep memory** (long-term, rarely accessed) | Memories that exist but resist retrieval. The tip-of-tongue phenomenon: you know the information is there, partial metadata is accessible (first letter, related concepts), but the full record takes time or the right cue. | Seconds to minutes | **Frozen tier** — maximum compression (zstd-19), archived. Longest retrieval time. Like recalling a name from twenty years ago. |

The brain's key insight: **you don't need all memories at full resolution all the time.** You need the right ones, fast, with the option to dig deeper. This plugin works the same way.

---

## What it does

### Increases your context window without increasing disk space

Instead of loading 500 raw files into a 128K token window, the engine:

1. **Indexes every artifact at registration** — extracts keywords and generates a compact summary (~10-20% of the original token cost). The index stays loaded. The full files don't.
2. **Compresses idle artifacts** — files you haven't touched in days get compressed 3-4x. Your disk footprint shrinks instead of growing.
3. **Serves summaries first** — when your assistant starts a session, it gets a budget-optimized block of the most relevant memory summaries. Not the full files.
4. **Expands on demand** — if a summary isn't enough, the assistant recalls the full artifact. Warm takes milliseconds. Cold takes longer. Frozen takes the longest.

The net effect: you fit **3-4x more knowledge** into the same context window, and the most relevant memories surface first.

### Disk space impact

| Tier | Compression Ratio | 100MB of artifacts becomes |
|------|------------------|---------------------------|
| Hot | 1x (none) | 100 MB |
| Warm | ~3.2x | ~31 MB |
| Cold | ~3.5x | ~29 MB |
| Frozen | ~3.8x | ~26 MB |

With tiering active, a year's worth of AI session data that would consume hundreds of megabytes stays under 50 MB — and the semantic index that makes it all searchable is typically under 1 MB.

---

## How tiering works — when and why artifacts move

### The decision engine

Every artifact is tracked with two timestamps: **age** (when it was created) and **last accessed** (when anything last read it). The engine uses both to decide when to compress:

| Transition | Age Threshold | Idle Threshold | What Happens |
|-----------|--------------|----------------|-------------|
| Hot → Warm | 48 hours old | 24h since last access | Compressed at zstd level 3. ~234 MB/s. Fast. |
| Warm → Cold | 14 days old | 7 days idle | Recompressed at zstd level 9. ~40 MB/s. Slower. |
| Cold → Frozen | 90 days old | 30 days idle | Recompressed at zstd level 19. ~3 MB/s. Archival. Deepest compression. |

Both conditions must be true. A 3-day-old file you accessed 1 hour ago stays hot. A 60-day-old file you haven't touched in a month moves to cold. A 6-month-old file nobody has looked at in 90 days goes frozen.

All thresholds are configurable in `config.json`.

### What triggers the check

Tiering runs when you execute `tiered-memory run`. You can automate this with a cron job, a Claude Code hook, or any scheduler. It's not a daemon — it's a single-pass scan-evaluate-compress cycle.

```bash
# Manual run
tiered-memory run

# Preview without changing anything
tiered-memory run --dry-run

# Automate (cron, every 6 hours)
0 */6 * * * cd /path/to/project && tiered-memory run
```

---

## How retrieval works — and how the AI knows where to look

This is the critical question: when your AI assistant needs a memory that's been compressed, how does it find it?

### The semantic index (the pointer system)

At registration time — before any compression happens — every artifact gets indexed. The engine extracts keywords, generates a summary, and stores this in a lightweight `semantic-index.json` file. This index is **always available, always fast, never compressed.** It's the equivalent of the hippocampus: a small structure that knows where everything is stored, even if the memories themselves are packed away.

```
semantic-index.json (~1 MB for 500+ artifacts)
  ├── artifact: session-2026-01-15.jsonl
  │   ├── tier: cold
  │   ├── summary: "142 entries, fields: turn, role, content — security audit discussion"
  │   ├── keywords: [security, audit, TARA, encryption, vulnerability]
  │   └── relevance_score: 0.0 (not yet scored against a query)
  ...
```

### The retrieval flow

```
AI assistant starts a session with query: "What did we discuss about TARA last month?"

Step 1: INDEX SCAN (instant, no decompression)
  → Search semantic-index.json for "TARA"
  → Hit: session-2026-02-10.jsonl (cold tier, score: 0.85)
  → Hit: memory/project_qif.md (warm tier, score: 0.60)
  → Hit: session-2026-01-05.jsonl (frozen tier, score: 0.40)

Step 2: SUMMARY LOAD (instant for all tiers)
  → Load summaries from index into context
  → "142 entries about security audit and TARA threat model"
  → Cost: ~50 tokens per artifact (vs ~2,000 for full content)

Step 3: PROGRESSIVE RECALL (only if summary isn't enough)
  → AI decides it needs full content of the top hit
  → Warm recall: decompress zstd-3 → ~10ms
  → Cold recall: decompress zstd-9 → ~50-200ms
  → Frozen recall: decompress zstd-19 → ~1-5 seconds
  → Full content loaded into context
```

### The AI never blindly searches cold/frozen

The index is the answer to "how does the AI know?" It doesn't guess. It doesn't decompress everything hoping to find something. The semantic index is a lightweight pointer system that says exactly what's in each tier, what keywords match, and how relevant each artifact is to the current task.

If the index has no match, there's nothing to recall. If it has a match in frozen, the AI knows it exists, knows the summary, and can decide whether the full recall is worth the wait.

### The colder the tier, the longer the retrieval

This is by design — the same tradeoff your brain makes:

| Tier | Decompression Speed | Typical Recall Time | Analogy |
|------|--------------------|--------------------|---------|
| Hot | No decompression | Instant (file read) | What you're thinking about right now |
| Warm | ~234 MB/s (zstd-3) | 5-50ms | What you did yesterday |
| Cold | ~40 MB/s (zstd-9) | 50-500ms | What happened last month |
| Frozen | ~3 MB/s (zstd-19) | 1-10 seconds | A name from twenty years ago |

If encryption is enabled, add the time to retrieve the private key from your vault and decrypt the DEK. For Keychain + Touch ID, this adds ~1-2 seconds (biometric prompt). For HashiCorp Vault, it depends on network latency.

The tradeoff is worth it: frozen artifacts take up the least disk space, have the smallest footprint in your context window (just an index entry), and only get fully recalled when specifically needed.

---

## Your AI's secrets are protected

Every conversation you have with an AI assistant, every memory it stores, every task it tracks — these are **your data**. Session logs contain your code, your decisions, your private thoughts. Memory files contain your preferences, your patterns, your identity.

Without encryption, this data sits in plaintext files on your disk. Anyone with access to your machine — a stolen laptop, a compromised backup, a shared server — can read every session you've ever had.

With tiered-memory-engine's encryption enabled:

- **Every artifact gets its own unique encryption key** (256-bit DEK). Compromising one file doesn't expose the others.
- **Each tier has independent keypairs.** Compromising your warm-tier key doesn't unlock cold or frozen data.
- **Your sessions, memories, and secrets are exactly as protected as the key and the method you use to store it.** Use macOS Keychain with Touch ID and your data is hardware-bound to your machine's Secure Enclave. Use HashiCorp Vault and it's protected by enterprise-grade access control. The encryption is only as strong as your key management.
- **Encryption requires only the public key.** The engine compresses and encrypts artifacts using just the public key in your config. The private key — the one that can actually read the data — is never on disk. It's retrieved on-demand from your vault, used, and zeroed from memory.

---

## Why post-quantum? Why not just use what works today?

### Classical encryption has a deadline

NIST published [IR 8547 (November 2024)](https://csrc.nist.gov/pubs/ir/2024/NIST.IR.8547.ipd.pdf) — the federal transition timeline for post-quantum cryptography:

- **By 2030:** RSA-2048, P-256, and all 112-bit classical algorithms **deprecated** for new systems
- **By 2035:** All RSA and ECC algorithms **disallowed entirely**

This isn't theoretical. It's a published federal mandate with a date on it.

The risk is "harvest now, decrypt later" — an adversary captures your encrypted data today, stores it, and decrypts it once quantum computers are capable. If your AI memory contains sensitive intellectual property, trade secrets, personal information, or security research, the data you encrypt today needs to survive until 2035 and beyond.

### Why introduce legacy encryption before the deadline when you can start with post-quantum now?

tiered-memory-engine uses **ML-KEM-768** (NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), finalized August 2024) — the NIST-standardized post-quantum Key Encapsulation Mechanism. It provides Category 3 security (~AES-192 equivalent) against both classical and quantum computers.

age v1.3.0+ implements ML-KEM-768 in **hybrid mode with X25519**: your data is protected by two independent algorithms simultaneously. Even if lattice-based cryptography is somehow broken in the future, the classical X25519 layer still holds. Even if a quantum computer breaks X25519, the ML-KEM-768 layer still holds. Both must fail for the encryption to break.

This is the same algorithm that [OpenSSH 10.0 made the default](https://www.openssh.org/pq.html) for all key exchange in April 2025.

**There is no reason to start with legacy crypto.** The post-quantum standard exists, the tooling is mature, and the performance overhead is negligible. Starting with classical encryption today means you'd need to migrate before 2030 anyway. Start with PQ and you're done.

### This is the most secure option — if you store your secrets safely and always rotate

Post-quantum encryption protects the algorithm. Key management protects the key. Both must be strong:

- **Store private keys in hardware** — macOS Keychain + Touch ID (Secure Enclave on Apple Silicon), YubiKey, or cloud HSMs. Never as plaintext files. The `file:` key source is deliberately blocked.
- **Rotate keys regularly** — key rotation re-wraps envelope headers in O(metadata), not O(data). The actual encrypted artifacts don't change. Rotate monthly or on any suspected compromise.
- **Use separate keypairs per tier** — warm and cold get independent keypairs. Compromising one doesn't expose the other.

---

## What makes this different from other plugins

| Feature | tiered-memory-engine | Typical memory plugin |
|---------|---------------------|----------------------|
| Compression | 4-tier automatic (hot/warm/cold/frozen) with production-grade zstd | None or simple gzip |
| Encryption | Post-quantum (ML-KEM-768) with per-artifact keys and envelope encryption | None, or single-key AES |
| Context enhancement | Semantic index + progressive recall + budget management | Load everything or nothing |
| Key management | Asymmetric — public encrypts, private decrypts from vault. Touch ID. No file keys. | Symmetric key in a file |
| AI-agnostic | Claude, ChatGPT, Cursor, Copilot, custom | Locked to one platform |
| Disk overhead | Index is <1 MB. Artifacts shrink 3-4x. | Grows linearly with usage |
| Security review | Red-team reviewed by 3 independent security personas | Self-reviewed |
| Brain-inspired | Mirrors human working/recent/long-term/deep memory with matching retrieval tradeoffs | Flat storage |

---

## Quick start

```bash
# Install
pip install -e .

# Initialize config (auto-detects Claude, ChatGPT, Cursor, Copilot artifacts)
tiered-memory init

# Scan — see what artifacts exist on your system
tiered-memory scan

# Preview what would be tiered (safe, no changes)
tiered-memory run --dry-run

# Run tiering
tiered-memory run

# Check status
tiered-memory status

# Get context-optimized memory for your AI session
tiered-memory context --query "your current task"

# Search memories across all tiers (uses the index, no decompression)
tiered-memory search "keyword"

# Recall a specific artifact back to hot tier
tiered-memory recall /path/to/original/file

# Set up post-quantum encryption
tiered-memory encrypt-setup
```

### Enable encryption (one command, Touch ID)

```bash
python3 -c "
from src.envelope import EnvelopeEncryptor
pub, src = EnvelopeEncryptor.setup_tier_with_keychain('warm')
print(f'Add to config.json:')
print(f'  warm pubkey: {pub}')
print(f'  warm source: {src}')
"
# Private key went straight from age-keygen → Keychain.
# It never existed as a file on disk.
```

## Supported AI assistants

| Assistant | Auto-detected Artifacts |
|-----------|------------------------|
| Claude Code | `~/.claude/subagents/*.jsonl`, project memory, todos, history |
| ChatGPT | Desktop app cache |
| Cursor | Conversation logs |
| GitHub Copilot | Configuration cache |
| Custom | Add any path to `config.json` |

## Architecture

| Component | Inspired By | What It Does |
|-----------|-------------|--------------|
| 4-tier transitions | Splunk SmartStore + S3 Intelligent-Tiering | Age + idle time trigger progressive compression |
| Compression | Splunk 7.2+ / ELK 8.17+ / Iceberg 1.4+ default | zstd at 4 levels (3, 9, 19) |
| Semantic index | Elasticsearch inverted index | Keyword search without decompressing |
| Progressive recall | ELK frozen-tier partially mounted snapshots | Summary → full content on demand |
| Envelope encryption | AWS KMS / Google Tink | Per-artifact DEK, asymmetric PQ key wrap |
| Context budget | Splunk license metering | Token-aware memory loading |
| Brain-inspired tiers | Working / episodic / semantic / deep memory | Retrieval speed matches access frequency |

## Security

- Post-quantum encryption (ML-KEM-768 + X25519 hybrid, NIST FIPS 203)
- Per-artifact encryption keys (compromise one artifact, others stay safe)
- Per-tier keypairs (compromise warm, cold stays safe)
- Forward secrecy (age uses ephemeral keys per encryption)
- Private key file source deliberately blocked — Keychain, Vault, KMS, or env only
- SHA-256 integrity verification on compress and recall
- Symlink protection, path containment, sensitive directory blocklist
- Unpredictable temp files with 0600 permissions
- Atomic writes, registry field filtering, no shell=True
- Red-team reviewed by 3 independent security personas (offensive, crypto, supply chain)

## Requirements

- Python 3.10+
- `zstandard` >= 0.19.0 (installed automatically)
- `age` >= 1.3.0 (optional, for PQ encryption) — `brew install age`

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT

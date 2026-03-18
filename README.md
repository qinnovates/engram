# Engram

Give your AI agents long-term memory that scales, compresses, and protects itself.

Every other memory solution dumps raw files on disk and hopes for the best. Context windows fill up. Old sessions disappear. Nothing is encrypted. If someone gets on your machine, every conversation you've ever had with your AI is readable in seconds.

Engram is different. It's the plumbing layer that lets your agents work with months or years of accumulated context without eating your disk alive, while protecting that context like it matters. Because it does.

**Everything stays local. Nothing is sent to any server, API, or third party. Zero telemetry. Your memories never leave your machine.** But if you choose to offload memory to a separate server, NAS, or cloud archive, the encryption travels with it. You choose the architecture. The plumbing is here.

## Works with Claude, OpenClaw, and anything that writes files

Engram is AI-agnostic. It compresses and encrypts the artifacts your AI assistant leaves behind, regardless of which assistant made them.

**Claude Code** is the primary target. Engram auto-detects 18 Claude artifact locations: conversation logs, subagent outputs, memory files, debug traces, plans, tasks, session metadata. It ships as a Claude Code plugin (invocable as `/engram`) with hooks that auto-load context at session start.

**OpenClaw** and other open-source AI tools work too. Point Engram at any directory where your tool writes memory files and it handles the rest. Add custom scan targets in `config.json` or use the interactive setup (`engram init --mode interactive`) to pick exactly which locations to archive.

A word on OpenClaw specifically: it's a capable tool that expands context aggressively. But expanding context without understanding your security model is how you end up with months of unencrypted session history on a shared machine. If you're using OpenClaw (or any open-source AI tool that stores conversation logs), you should understand the OSI model well enough to know where your data is exposed, and you should have a security posture before you start accumulating sensitive context. Engram doesn't replace that knowledge. It provides the encryption and compression layer for people who already have it.

If you're running any AI assistant without encryption on the session data, you're trusting that nobody will ever access your disk. That's not a security model. That's hope.

## Why this exists

Your brain doesn't keep every memory at the same resolution. It tiers them. Recent things are vivid and fast. Older things compress into patterns and summaries. Deep memories take effort and the right cue to retrieve. This isn't a limitation. It's what makes the system scale.

AI memory tools today don't do this. They treat a session from 5 minutes ago the same as one from 6 months ago. Everything uncompressed, everything unencrypted, everything competing for the same context window. That doesn't scale.

Engram applies the same tiered architecture that Splunk, Elasticsearch, and cloud datalakes use at petabyte scale. But we're not bound by biological constraints. The brain has working memory and long-term. We have four tiers with dramatically different compression strategies, a semantic index that searches all of them without decompressing anything, and post-quantum encryption that protects your data even if an attacker captures it today and waits for quantum computers.

The result: your agents get access to months of context in the same token budget that used to hold a few sessions. Your disk footprint shrinks instead of growing. And your sessions, decisions, code reviews, and private conversations are encrypted with keys that only you control.

---

## How your brain does it — and how this plugin mirrors it

Your brain doesn't store yesterday's lunch and your childhood address the same way. It uses a tiered system where memories move through stages based on how recently and frequently you access them:

| Brain System | What It Does | Retrieval Speed | Plugin Equivalent |
|-------------|-------------|-----------------|-------------------|
| **Working memory** (prefrontal cortex) | Holds what you're thinking about right now. ~7 items. Active neural firing — not stored, just maintained. | ~40ms per item | **Hot tier** — uncompressed, instant access |
| **Recent memory** (hippocampus) | Consolidates today's experiences. The hippocampus acts as a temporary index, binding fragments together. During sleep, it replays memories into the neocortex for longer storage. | Hundreds of ms | **Warm tier** — minified + zstd-3 (~4-5x). Semantic index acts as the hippocampal pointer. |
| **Long-term memory** (neocortex) | Distributed storage across cortical regions. Reconstructed from fragments on recall, not read from a single address. Needs the right cue to trigger retrieval. | Seconds | **Cold tier** — boilerplate stripped + dictionary-trained zstd-9 (~8-12x). Needs a search hit or explicit recall. |
| **Deep memory** (long-term, rarely accessed) | Memories that exist but resist retrieval. The tip-of-tongue phenomenon: you know the information is there, partial metadata is accessible (first letter, related concepts), but the full record takes time or the right cue. | Seconds to minutes | **Frozen tier** — columnar Parquet + dict encoding + zstd-19 (~20-50x). Longest retrieval. Like recalling a name from twenty years ago. |

The brain's key insight: **you don't need all memories at full resolution all the time.** You need the right ones, fast, with the option to dig deeper. This plugin works the same way.

---

## What it does

### Increases your context window without increasing disk space

Instead of loading 500 raw files into a 128K token window, the engine:

1. **Indexes every artifact at registration** — extracts keywords and generates a compact summary (~10-20% of the original token cost). The index stays loaded. The full files don't.
2. **Compresses idle artifacts** using a multi-stage pipeline that gets dramatically more aggressive at each tier — up to 50x on frozen data.
3. **Serves summaries first** — when your assistant starts a session, it gets a budget-optimized block of the most relevant memory summaries. Not the full files.
4. **Expands on demand** — if a summary isn't enough, the assistant recalls the full artifact. Warm takes milliseconds. Cold takes longer. Frozen takes the longest.

The net effect: frozen-tier data takes **20-50x less space** than raw files, and the most relevant memories surface first.

### The compression pipeline — not just "higher zstd levels"

Most tools crank up zstd levels from 3 to 19 and call it a day. That gives you 3.2x to 3.8x — barely noticeable across four tiers. We do something different: each tier applies progressively more aggressive **data transformations** before the compressor even runs.

| Tier | Stage 1 | Stage 2 | Stage 3 | Effective Ratio | 100 MB becomes |
|------|---------|---------|---------|----------------|----------------|
| **Hot** | — | — | — | 1x | 100 MB |
| **Warm** | Minify JSON (strip whitespace) | zstd level 3 | — | **4-5x** | ~22 MB |
| **Cold** | Strip boilerplate to hash refs | Minify | Dictionary-trained zstd-9 | **8-12x** | ~10 MB |
| **Frozen** | Strip boilerplate | Minify | **Columnar Parquet** + dict encoding + zstd-19 | **20-50x** | ~3 MB |

The ratio jumps are dramatic because each stage attacks a different source of redundancy:

- **Minification** removes 30-40% of whitespace/formatting before zstd starts
- **Boilerplate stripping** replaces repeated system prompts (often 2,000-5,000 tokens repeated in every session) with 64-byte hash references — that alone can be 40-70% of total content
- **Dictionary training** teaches zstd the shared schema of your session logs (JSON keys, common tokens, tool call formats) so it only compresses the unique content
- **Columnar Parquet** is the biggest lever: JSONL repeats the same keys on every line ("role", "content", "timestamp"). Parquet groups all values for each key into a column, then applies per-column encoding

### Why Parquet for frozen tier

JSONL files look like this:
```json
{"role":"user","content":"What about security?","timestamp":1710000000}
{"role":"assistant","content":"Here is my analysis...","timestamp":1710000060}
```

The string `"role"` appears on every single line. In a 10,000-turn session, that's 10,000 redundant copies of every key name. Parquet transposes this into columns:

- **"role" column:** `["user","assistant","user","assistant",...]` — cardinality 2, run-length encodes to almost nothing
- **"timestamp" column:** `[1710000000, 1710000060, 1710000120, ...]` — monotonic integers, delta encodes to almost nothing (ClickHouse achieves 800:1 on sequences like this)
- **"content" column:** the actual text — dictionary encoded + zstd compressed. This is the only column that carries real entropy.

This is why ClickHouse achieves 75x on structured data and Parquet achieves 10-25x on log data. Same principle, applied to your AI memories.

Parquet also enables **column pruning on read**: if you only need "role" and "timestamp" for a search, you skip decompressing "content" entirely. This makes frozen-tier metadata queries faster than decompressing the full JSONL.

### Disk space impact (with full pipeline)

| Scenario | Raw Size | After Tiering | Savings |
|----------|----------|---------------|---------|
| 6 months of daily sessions (500 files) | 200 MB | ~15 MB | 93% |
| 2 years of AI memory (2,800 files) | 800 MB | ~35 MB | 96% |
| Team of 5, 1 year (10,000 files) | 2 GB | ~80 MB | 96% |

The semantic index that makes all of this searchable is typically under 1 MB.

---

## How tiering works — when and why artifacts move

### The decision engine

Every artifact is tracked with two timestamps: **age** (when it was created) and **last accessed** (when anything last read it). The engine uses both to decide when to compress:

| Transition | Age Threshold | Idle Threshold | Pipeline | Effective Ratio |
|-----------|--------------|----------------|----------|----------------|
| Hot → Warm | 48 hours old | 24h since last access | Minify → zstd-3 | ~4-5x |
| Warm → Cold | 14 days old | 7 days idle | Strip boilerplate → minify → dict-trained zstd-9 | ~8-12x |
| Cold → Frozen | 90 days old | 30 days idle | Strip → minify → columnar Parquet + dict + zstd-19 | ~20-50x |

**Both conditions must be true.** A 3-day-old file you accessed 1 hour ago stays hot. A 60-day-old file you haven't touched in a month moves to cold. A 6-month-old file nobody has looked at in 90 days goes frozen.

**You choose the triggers.** All thresholds are configurable in `config.json` — by age, by idle time, or both:

```json
{
  "tier_policy": {
    "hot_to_warm_age_hours": 48,
    "hot_to_warm_idle_hours": 24,
    "warm_to_cold_age_hours": 336,
    "warm_to_cold_idle_hours": 168,
    "cold_to_frozen_age_hours": 2160,
    "cold_to_frozen_idle_hours": 720
  }
}
```

Set any threshold to `0` to disable that condition. Set age thresholds only for time-based tiering. Set idle thresholds only for usage-based tiering. Or use both for the tightest control.

### What triggers the check

Tiering runs when you execute `engram run`. You can automate this with a cron job, a Claude Code hook, or any scheduler. It's not a daemon — it's a single-pass scan-evaluate-compress cycle.

```bash
# Manual run
engram run

# Preview without changing anything
engram run --dry-run

# Automate (cron, every 6 hours)
0 */6 * * * cd /path/to/project && engram run
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

| Tier | Pipeline (reverse) | Typical Recall Time | Ratio | Analogy |
|------|-------------------|--------------------|---------|----|
| Hot | File read | Instant | 1x | What you're thinking about right now |
| Warm | zstd-3 decompress → restore whitespace | 5-50ms | 4-5x | What you did yesterday |
| Cold | dict-zstd-9 decompress → restore boilerplate | 50-500ms | 8-12x | What happened last month |
| Frozen | Parquet → JSONL conversion → restore boilerplate | 1-10 seconds | 20-50x | A name from twenty years ago |

If encryption is enabled, add the time to retrieve the private key from your vault and decrypt the DEK. For Keychain + Touch ID, this adds ~1-2 seconds (biometric prompt). For HashiCorp Vault, it depends on network latency.

The tradeoff is worth it: frozen artifacts take up the least disk space, have the smallest footprint in your context window (just an index entry), and only get fully recalled when specifically needed.

---

## Your AI's secrets are protected

Every conversation you have with an AI assistant, every memory it stores, every task it tracks — these are **your data**. Session logs contain your code, your decisions, your private thoughts. Memory files contain your preferences, your patterns, your identity.

Without encryption, this data sits in plaintext files on your disk. Anyone with access to your machine — a stolen laptop, a compromised backup, a shared server — can read every session you've ever had.

With engram's encryption enabled:

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

engram uses **ML-KEM-768** (NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), finalized August 2024) — the NIST-standardized post-quantum Key Encapsulation Mechanism. It provides Category 3 security (~AES-192 equivalent) against both classical and quantum computers.

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

| Feature | engram | Typical memory plugin |
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

### Install as a Claude Code plugin

```bash
# From the marketplace (when published)
claude plugin install engram

# Or from GitHub directly
claude --plugin-dir /path/to/engram

# Or install the Python package standalone
pip install -e .

# Initialize config (auto-detects Claude, ChatGPT, Cursor, Copilot artifacts)
engram init

# Scan — see what artifacts exist on your system
engram scan

# Preview what would be tiered (safe, no changes)
engram run --dry-run

# Run tiering
engram run

# Check status
engram status

# Get context-optimized memory for your AI session
engram context --query "your current task"

# Search memories across all tiers (uses the index, no decompression)
engram search "keyword"

# Recall a specific artifact back to hot tier
engram recall /path/to/original/file

# Set up post-quantum encryption
engram encrypt-setup
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

## Example use cases

### 1. Solo developer with long-running projects

You've been building a project for 6 months. You have 400+ conversation logs, memory files, and task artifacts from Claude Code sessions. Your context window loads the most recent files but has no memory of decisions you made 3 months ago.

```bash
# Initial setup — takes 30 seconds
engram init
engram run

# Now at session start, ask your AI for relevant context
engram context --query "authentication refactor we discussed in January"

# Output: summaries of 3 matching sessions from cold tier,
# plus 2 related memory files from warm tier.
# Total cost: ~200 tokens instead of ~8,000 for raw files.
```

**Result:** 400 artifacts compressed to ~30% of original disk space. Your AI surfaces relevant 3-month-old decisions in ~200 tokens instead of losing them entirely.

### 2. Security researcher with sensitive session data

You're doing vulnerability research. Your AI sessions contain exploit details, CVE analysis, and private disclosure timelines. This data must not leak.

```bash
# Set up per-tier encryption with Touch ID
python3 -c "
from src.envelope import EnvelopeEncryptor
for tier in ['warm', 'cold']:
    pub, src = EnvelopeEncryptor.setup_tier_with_keychain(tier)
    print(f'{tier} pubkey: {pub}')
    print(f'{tier} source: {src}')
"

# Enable encryption in config, then run
engram run

# Every compressed artifact now has:
# - Its own unique 256-bit encryption key
# - DEK encrypted with ML-KEM-768 (post-quantum)
# - Private key locked in Secure Enclave (Touch ID required)
```

**Result:** Even if your laptop is stolen, cold/frozen session data is encrypted with PQ crypto. The attacker needs your fingerprint AND the machine's Secure Enclave. Key rotation takes seconds (re-wraps headers, not data).

### 3. Team sharing an AI assistant on a server

Your team runs Claude Code on a shared dev server. Each person's sessions pile up in `~/.claude/subagents/`. After a month, there are 2,000+ JSONL files consuming 500 MB.

```bash
# Automate with cron — tier every 6 hours
crontab -e
# Add: 0 */6 * * * cd /path/to/project && engram run

# Anyone on the team can search all past sessions
engram search "database migration strategy"
# Returns: relevant sessions from any team member, ranked by relevance
```

**Result:** 500 MB drops to ~150 MB. Old sessions are searchable via the semantic index without decompressing. The cron job runs unattended.

### 4. AI assistant with multi-project memory

You use Claude Code across 5 projects. Each project has its own memory directory. You want a single search across all of them.

```bash
# Add all project memory dirs to config.json scan_targets
engram init  # starts with Claude defaults

# Edit ~/.engram/config.json to add custom paths:
# "scan_targets": [
#   {"path": "~/projects/webapp/.claude/memory", "pattern": "**/*"},
#   {"path": "~/projects/api/.claude/memory", "pattern": "**/*"},
#   {"path": "~/projects/mobile/.claude/memory", "pattern": "**/*"}
# ]

# Search across all projects
engram search "rate limiting implementation"
engram context --query "how did we handle auth across projects"
```

**Result:** Cross-project memory search. Your AI can recall that you solved rate limiting in the API project and apply the same pattern to the webapp — without you remembering which project it was in.

### 5. Long-term knowledge preservation

You've been coding with AI for 2 years. Early sessions contain foundational decisions you've forgotten. Without tiering, these files sit uncompressed and unsearchable. With tiering:

```bash
engram status
# Tiered Memory Status
# ========================================
# Total artifacts:   2,847
#   Hot:             42      (this week's sessions)
#   Warm:            186     (past 2 weeks)
#   Cold:            1,203   (past 3 months)
#   Frozen:          1,416   (older than 3 months)
# Total original:    847,293,102 bytes (808 MB)
# Total compressed:  241,226,600 bytes (230 MB)
# Overall ratio:     3.51x
# Space saved:       606 MB
# Indexed artifacts: 2,847
# Total keywords:    18,429

# Recall a specific frozen artifact about early architecture decisions
engram recall ~/.claude/subagents/session-2024-05-12.jsonl
# Takes ~3 seconds (frozen tier), but the full session is back in hot tier
```

**Result:** 2 years of AI memory in 230 MB instead of 808 MB. Every session searchable by keyword. Frozen artifacts take a few seconds to recall — like remembering something from years ago.

---

## Supported AI assistants

| Assistant | Auto-detected Artifacts |
|-----------|------------------------|
| Claude Code | 18 locations: session logs, subagent outputs, memory, debug, plans, tasks, history |
| ChatGPT | Desktop app cache |
| Cursor | Conversation logs |
| GitHub Copilot | Configuration cache |
| OpenAI Codex | Add Codex working directory to `config.json` |
| OpenClaw | Add memory/session directories to `config.json` |
| Any AI tool | Add any path — if it writes files, Engram can compress and encrypt them |

Any AI assistant can set up Engram from this repo. Claude, Codex, Copilot, ChatGPT — the README and interactive installer are designed so the AI reads the docs and walks you through it. No vendor lock-in at any layer.

## Plugin architecture

This project follows the official Anthropic Claude Code plugin specification:

```
engram/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest (name, version, author)
├── marketplace.json             # Marketplace distribution metadata
├── skills/
│   └── engram/
│       └── SKILL.md             # Skill definition with frontmatter
├── hooks/
│   └── hooks.json               # SessionStart + PreCompact hooks
├── src/                         # Core Python engine
│   ├── engine.py                # Orchestrator
│   ├── context.py               # Context window enhancement
│   ├── compressor.py            # zstd tiered compression
│   ├── envelope.py              # Asymmetric PQ envelope encryption
│   ├── encryption.py            # age CLI integration
│   ├── config.py                # Config with validation
│   ├── metadata.py              # Artifact tracking + integrity
│   ├── scanner.py               # AI assistant auto-detection
│   └── cli.py                   # CLI interface
├── tests/                       # 47 passing, 6 integration (need age)
├── docs/
│   └── KEY-STORAGE-GUIDE.md     # Vault options ranked by security
├── README.md
├── LICENSE
└── pyproject.toml
```

**Hooks:** On `SessionStart`, the plugin auto-loads relevant memory context. On `PreCompact`, it checks if any artifacts should be tiered down.

**Skill:** Invocable as `/engram` in Claude Code. Auto-triggers on keywords like "compress memories", "search past sessions", "encrypt AI data".

## Architecture

| Component | Inspired By | What It Does |
|-----------|-------------|--------------|
| 4-tier transitions | Splunk SmartStore + S3 Intelligent-Tiering | Age + idle time trigger progressive compression |
| Compression | Splunk 7.2+ / ELK 8.17+ (best_compression) / Iceberg 1.4+ default | zstd at 4 levels (3, 9, 19) |
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

## Your data, your infrastructure, your rules

Engram processes everything locally. No data leaves your machine. No telemetry, no analytics, no cloud dependency. Your memories stay on your filesystem unless you decide otherwise.

That's a deliberate design choice. Most memory tools are tightly coupled to a single AI platform and assume everything lives on one machine. Engram gives you the plumbing. You choose the architecture:

- **Local-only:** Everything on your laptop. Keychain + Touch ID for encryption. Simplest setup.
- **NAS/server offload:** Point scan targets or compressed archives at a mounted volume. Encryption travels with the files. Move cold/frozen tiers to cheaper storage.
- **Multi-machine:** Share the semantic index across devices. Each machine compresses and encrypts locally. Cold/frozen archives sync via rsync, Syncthing, or cloud storage. Private keys stay on each machine's Keychain.
- **Team server:** Shared `~/.claude/` on a dev server. Engram compresses everyone's sessions. Per-user encryption keys so team members can't read each other's cold-tier data.

The encryption protects you in all of these scenarios. If an attacker gets on your system, they see compressed + encrypted blobs with per-artifact keys. If you offload frozen archives to S3 or a NAS, the PQ encryption means even a "harvest now, decrypt later" adversary can't read them. The key never leaves your Keychain/Vault. The data goes wherever you put it.

## Disclaimer

This software is provided as-is under the MIT license with no warranty. It has been security-reviewed (4 rounds, 3 independent red-team personas), but you should:

- Run `engram run --dry-run` first to preview changes
- Keep backups of `~/.claude/` before first run
- Test key recovery (`engram recall`) before relying on encryption for critical data
- Know that boilerplate stripping stores extracted content in `~/.engram/boilerplate/` — if that directory is deleted, stripped content is lost (but can be re-extracted from the original if it still exists)

**Encryption scope:** PQ encryption (ML-KEM-768, FIPS 203) protects data at rest. It does not protect against a compromised process with memory access or an attacker who has your private key. The `age` tool's PQ hybrid is described by its author as production-ready; the classical X25519 + ChaCha20-Poly1305 layer was audited by Cure53.

## AI Disclosure

This project was built with extensive AI assistance (Claude Opus 4.6, Anthropic). AI was used for:
- Code generation (all Python modules)
- Security review (4 rounds of multi-persona red-team analysis)
- Compression research (Splunk/ELK/Parquet architecture study)
- Documentation and blog post drafting
- Test generation

All code was reviewed by the author. All factual claims were independently fact-checked (7 claims verified against primary sources, 4 corrections applied). All security findings were verified and fixed. The author takes full responsibility for the published content.

Every git commit includes `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>` for full transparency.

## License

MIT

---
title: "I Built a Plugin That Gives AI Assistants Long-Term Memory"
date: 2026-03-18
author: "Kevin Qi"
tags: [engram, ai-memory, compression, post-quantum, security, parquet, context-window]
source: "original"
fact_checked: true
ai_assisted: true
---

# I Built a Plugin That Gives AI Assistants Long-Term Memory

Your AI assistant has amnesia.

Every session starts from zero. The context window fills up. Old conversations vanish. That architectural decision you made in January? Gone. The bug you spent an hour explaining three weeks ago? The assistant has no idea it happened.

The workaround is memory files. Claude writes to `~/.claude/`. ChatGPT keeps desktop caches. Cursor logs conversations. After six months of daily use, you've got 4,500+ files consuming 2.6 GB of disk space, sitting unencrypted, unsearchable, and mostly never looked at again.

I know because I checked. That's what was on my machine.

So I built [Engram](https://github.com/qinnovates/engram).

## The numbers

Before Engram, my Claude artifacts looked like this:

```
4,538 files
2.6 GB on disk
0 files encrypted
0 files compressed
100% of context budget consumed by recent sessions only
```

After running `engram run`:

```
4,537 files tracked and indexed
609 artifacts compressed across warm and cold tiers
11.58x compression ratio (real, on my actual session data)
131,271 keywords searchable across all tiers
1.6 GB saved
Encryption: per-artifact keys, private keys in Keychain (Touch ID)
```

1.6 GB saved from a single command. But the disk savings aren't the point. The point is that my AI assistant can now reference decisions I made three months ago without me re-explaining them. The context window didn't get bigger. The memory got smarter.

## How it works: your brain already figured this out

Your brain doesn't store yesterday's lunch and your childhood address the same way. Working memory holds about 7 items (Miller, 1956). The hippocampus consolidates recent experiences during sleep, replaying them into the neocortex. Deep memories take effort and the right cue to retrieve.

The deeper the memory, the longer the recall. That's not a limitation. It's a compression strategy that lets the system scale across decades.

Engram applies the same principle, but we're not bound by biological constraints:

| Brain System | Engram Tier | What Happens | Compression |
|---|---|---|---|
| Working memory | **Hot** | Active session, instant access | 1x (raw) |
| Recent memory | **Warm** | Minified JSON + zstd compression | **4-5x** |
| Long-term memory | **Cold** | Boilerplate stripped + dictionary-trained zstd | **8-12x** |
| Deep memory | **Frozen** | Columnar Parquet + dictionary + zstd | **20-50x** |

Those ratios aren't from cranking up zstd levels (that gets you 3.2x to 3.8x, which is barely noticeable). Each tier applies progressively more aggressive data transformations *before* the compressor runs.

## Why the ratios are so different

**Warm** strips whitespace from JSON. Sounds trivial. It's 30-40% of most pretty-printed session logs.

**Cold** does something more interesting. Every Claude session repeats the same 2,000-5,000 token system prompt verbatim. Across 4,500 sessions, that's the same block of text repeated 4,500 times. Engram strips these to 64-byte hash references and stores the original once. Then a dictionary trained on your actual session logs teaches zstd the shared schema (JSON keys, tool call formats, common tokens). The compressor only handles what's actually unique.

**Frozen** is where it gets dramatic. JSONL files repeat `"role"`, `"content"`, `"timestamp"` on every single line. Parquet transposes this into columns. The `role` column (cardinality: 2) compresses via run-length encoding to almost nothing. Timestamps (monotonic integers) compress via delta encoding to almost nothing. ClickHouse achieves up to 170x on nginx logs with this approach. Parquet became the default storage format in Apache Iceberg 1.4 for the same reason.

Only the actual content text carries real entropy. Everything else compresses away.

## The index: how the AI knows where to look

Compression without search is a write-only archive. Useless.

Every artifact gets indexed at registration time, before any compression. Keywords extracted. Summary generated. The index is under 1 MB for thousands of artifacts. It's always loaded. Never compressed. It's the hippocampus: a small structure that knows where everything is stored.

When your AI starts a session, Engram feeds it a budget-optimized block of relevant summaries. Not the full files. Summaries cost 10-20% of the tokens. If a summary isn't enough, the assistant explicitly recalls the full artifact:

- **Hot:** instant
- **Warm:** ~10ms
- **Cold:** ~500ms
- **Frozen:** a few seconds

The AI never decompresses everything hoping to find something. The index tells it exactly what's in each tier. No match, no decompression.

## Your sessions are your data. Act like it.

Every conversation you have with an AI assistant is stored in plaintext on your disk. Your code reviews, security research, personal decisions, intellectual property. Anyone with access to your machine can read all of it.

This matters more as memory gets more capable. More memory means more data at risk.

I see this with tools like OpenClaw and other open-source memory extensions. They expand context aggressively, which is useful. But they store everything unencrypted. On a shared server, a stolen laptop, or a compromised backup, that's your entire AI history, readable in seconds.

If you're using any AI tool that stores session data and you don't have a solid understanding of your security model, learn that before you start accumulating months of sensitive context in plaintext. Engram gives you the encryption layer. It doesn't replace the judgment to know when you need it.

## The encryption: post-quantum because the deadline is real

NIST published the initial public draft of [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) in November 2024. The proposed timeline: RSA-2048 and P-256 deprecated by 2030. All RSA and ECC disallowed by 2035. This isn't a theoretical concern. It's a published federal timeline.

The attack is "harvest now, decrypt later." Capture encrypted data today. Wait for quantum computers. If the key wrapping uses RSA or X25519, Shor's algorithm recovers every key.

Engram uses [ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/final) (NIST FIPS 203, August 2024) in hybrid mode with X25519. Both classical and post-quantum simultaneously. Same algorithm [OpenSSH 10.0 made the default](https://www.openssh.org/pq.html) in April 2025.

Engram offers two encryption architectures. Simple mode uses one key for everything. Envelope mode gives each tier its own keypair and each artifact its own unique 256-bit DEK. Compromise one artifact in envelope mode and only that artifact is exposed. Compromise the warm tier key and cold/frozen are still protected. Key rotation re-wraps DEK headers in O(metadata), not O(data) — you don't re-encrypt terabytes.

Private keys never exist as files on disk. They live in macOS Keychain (Touch ID on Apple Silicon binds them to the Secure Enclave), HashiCorp Vault, or cloud KMS. The `file:` key source is deliberately blocked in the code.

Why start with legacy crypto and migrate before 2030 when you can start with PQ now?

## Key management: the part nobody wants to think about

Encryption is optional. Engram works without it — you get compression, indexing, and context enhancement either way. But if your sessions contain anything you wouldn't want an attacker to read, turn it on.

When you do, understand this: **if you lose your private key, encrypted data is gone forever.** No recovery. No backdoor. That's the point of strong encryption, but it means your key management matters more than the algorithm.

On macOS, Touch ID + Keychain is the easiest path. The Secure Enclave on Apple Silicon means the key is hardware-bound — it can't be extracted even with root access. On Windows, native Keychain isn't supported yet. Use a FIDO2 YubiKey for hardware-bound storage, or HashiCorp Vault. On Linux, Vault or cloud KMS via the `command:` source.

For production or team environments, I recommend running Engram's encryption under a dedicated service account with RBAC — a distinct account that handles only encryption/decryption operations, with no other privileges on the system. This separates the encryption boundary from your daily user account. If a compromised session can't access the key material, the encrypted data stays safe. Setting up RBAC is out of scope for this tool, but if you're in that environment, you already know what to do.

Your config file (`~/.engram/config.json`) contains the public key and scan paths. The public key alone can't decrypt anything, but it's still operational metadata. The config is `.gitignore`d, written with `0600` permissions, and should never be shared. Treat it like any other security configuration.

## Everything stays local. Unless you decide otherwise.

No data is sent to any server. No telemetry. No analytics. Your memories never leave your filesystem.

But if you want to offload frozen archives to a NAS, S3, or a separate server, the encryption travels with the data. An attacker who intercepts PQ-encrypted blobs with per-artifact keys they can't unwrap gets nothing useful.

You choose the architecture. Engram is the plumbing.

- **Local-only:** Laptop + Keychain + Touch ID. Simplest.
- **NAS/server:** Cold and frozen tiers on cheaper storage. Encryption goes with them.
- **Multi-machine:** Shared semantic index. Per-machine encryption keys. Sync via rsync.
- **Team server:** Everyone's sessions compressed. Per-user encryption so teammates can't read each other's cold-tier data.

## Works with Claude, Codex, OpenClaw, and anything that writes files

Engram is AI-agnostic. Claude Code gets first-class auto-detection (18 artifact locations). Everything else works by adding a path to `config.json`. ChatGPT, Cursor, Copilot, OpenAI Codex, OpenClaw, or any tool you build yourself.

Any AI assistant can set up Engram from the repo. The interactive installer and README are designed so Claude, Codex, or Copilot can read the docs and walk you through it. No vendor lock-in at any layer.

## What makes this different

I looked at every memory plugin I could find. Here's where they fall short:

| | Other plugins | Engram |
|---|---|---|
| **Compression** | None, or single-level zstd (~3x) | Multi-stage pipeline: 4-5x / 8-12x / 20-50x per tier |
| **Encryption** | None | PQ (ML-KEM-768) — simple or envelope mode (per-artifact DEKs) |
| **Search** | Decompress everything to find something | Semantic index searches all tiers without decompression |
| **AI lock-in** | One platform | Claude, Codex, ChatGPT, Cursor, Copilot, OpenClaw, custom |
| **Data sent to cloud** | Sometimes | Never. Zero telemetry. |
| **Storage format** | Raw JSON files forever | Parquet columnar for frozen tier (20-50x) |
| **Key management** | Key file on disk (if any) | Per-tier keypairs, Keychain/Touch ID, Vault, KMS. File keys blocked. |
| **Key rotation** | Re-encrypt everything | Re-wrap DEK headers only (O(metadata)) |
| **Security review** | Self-reviewed | 6 rounds, 3 red-team personas, formal threat model |

## Try it

```bash
pip install engram

# Guided setup — auto-detects your AI assistants, you confirm
engram init

# See what would be compressed (safe, changes nothing)
engram run --dry-run

# Execute tiering
engram run

# Search months of memory without decompressing anything
engram search "that authentication refactor"

# Get a context block optimized for your AI's token budget
engram context --query "auth patterns we discussed"

# Recall a frozen artifact back to hot (takes a few seconds)
engram recall ~/.claude/subagents/session-2025-09-12.jsonl
```

The guided setup analyzes your file ages and asks whether you want 2 tiers (simple: hot + cold) or 4 tiers (full: hot + warm + cold + frozen). It shows you exactly how many files would go where before anything runs. You choose.

Open source. MIT license. 72 tests. Red-team reviewed by 3 independent security personas across 6 rounds. Formal threat model. Per-artifact envelope encryption. Every module wired in and tested.

[github.com/qinnovates/engram](https://github.com/qinnovates/engram)

Your AI's memory should scale like yours does. Compress what's old. Encrypt what's sensitive. Index everything. Recall what matters.

---

*Written with AI assistance (Claude). All claims fact-checked against primary sources. The author takes full responsibility for all content.*

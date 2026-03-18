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

Every session starts from zero. The context window fills up. Old conversations vanish. That thing you spent an hour explaining three weeks ago? Gone. The architectural decision you made in January? The assistant has no idea.

The workaround is memory files. Claude Code writes to `~/.claude/projects/*/memory/`. ChatGPT keeps desktop caches. Cursor logs conversations. These files grow without bound, sit unencrypted on your disk, and most of them never get looked at again.

I wanted something better. So I built Engram.

## Your brain already solved this problem

Your brain doesn't store yesterday's lunch and your childhood address the same way. It uses a tiered system. Working memory holds about 7 items in active neural firing. The hippocampus consolidates recent experiences during sleep, replaying them into the neocortex for long-term storage. Older memories live distributed across cortical regions, reconstructed from fragments when the right cue triggers recall.

The deeper the memory, the longer it takes to retrieve. That's not a bug. It's a compression strategy.

Engram works the same way.

| Brain System | What Happens | Engram Equivalent |
|---|---|---|
| Working memory (prefrontal cortex) | ~7 items, active firing, instant access | **Hot tier** — raw files, no compression |
| Recent memory (hippocampus) | Consolidation, indexing, hours to days | **Warm tier** — minified + zstd, 4-5x compression |
| Long-term memory (neocortex) | Distributed storage, cue-dependent recall | **Cold tier** — boilerplate stripped + dictionary-trained zstd, 8-12x |
| Deep memory (rarely accessed) | Tip-of-tongue, takes seconds or the right cue | **Frozen tier** — columnar Parquet + zstd, 20-50x |

The brain's key insight: you don't need all memories at full resolution all the time. You need the right ones fast, with the option to dig deeper.

## How the compression pipeline works

Most tools crank up the zstd level and call it a day. zstd level 3 gives you 3.2x. zstd level 19 gives you 3.8x. Across four tiers, that's barely noticeable.

We do something different. Each tier applies progressively more aggressive data transformations *before* the compressor even runs.

**Warm (4-5x):** JSON minification strips 30-40% of whitespace. Then zstd-3 handles the rest.

**Cold (8-12x):** AI session logs repeat the same system prompts in every single session. A 2,000-5,000 token system prompt, verbatim, thousands of times across your history. Engram strips these to 64-byte hash references and stores the original once. That alone can eliminate 40-70% of content. Then a dictionary trained on your actual session logs teaches zstd the shared schema, so it only compresses the unique content.

**Frozen (20-50x):** This is where Parquet comes in.

## Why Parquet for frozen tier

A JSONL conversation log looks like this:

```json
{"role":"user","content":"What about security?","timestamp":1710000000}
{"role":"assistant","content":"Here is my analysis...","timestamp":1710000060}
```

The string `"role"` appears on every single line. In a 10,000-turn session, that's 10,000 redundant copies of every key name.

Parquet transposes this into columns. The `role` column has cardinality 2 ("user" and "assistant"). Run-length encoded, it compresses to almost nothing. The `timestamp` column is monotonically increasing integers. Delta encoded, it compresses to almost nothing. Only the `content` column carries real entropy.

This is why ClickHouse achieves up to 170x on nginx logs with optimal codecs. This is why every modern data lake uses Parquet (it became the default format in Apache Iceberg 1.4). Same principle, applied to your AI memories.

Parquet also enables column pruning on read. If you only need the `role` and `timestamp` columns for a search, you skip decompressing `content` entirely. Frozen-tier metadata queries can be faster than decompressing the full JSONL.

## The semantic index: how the AI knows where to look

Compression without search is useless. If you can't find a memory, it doesn't matter how efficiently it's stored.

At registration time, before any compression happens, every artifact gets indexed. Keywords extracted. Summary generated. This index is small (under 1 MB for thousands of artifacts), always loaded, never compressed. It's the hippocampus of the system: a small structure that knows where everything is stored, even when the memories themselves are packed away in cold or frozen tier.

When your AI assistant starts a session, it gets a budget-optimized block of the most relevant memory summaries. Not the full files. Summaries cost 10-20% of the tokens. If a summary isn't enough, the assistant explicitly recalls the full artifact. Cold recall takes ~500ms. Frozen takes a few seconds. Like remembering a name from years ago.

The AI never blindly searches compressed archives. The index tells it exactly what's there. If the index has no match, there's nothing to decompress.

## Your AI sessions are your data. Protect them.

Here's what most people don't think about: every conversation you have with an AI assistant is stored in plaintext files on your disk. Your code reviews, your security research, your personal decisions, your intellectual property. Anyone with access to your machine can read all of it.

This matters more as memory systems get more capable. More memory means more data at risk. If you're expanding your AI's context without encrypting it, you're building a bigger target.

I see this with tools like OpenClaw and other open-source memory extensions. They expand context aggressively, which is useful. But they store everything unencrypted. On a shared server, a stolen laptop, or a compromised backup, that's every session you've ever had, readable in seconds.

Engram runs entirely on your local machine. No data is sent to any server, API, or cloud service. There is no telemetry. Your memories never leave your filesystem. The encryption is optional but designed for this threat model:

- Every artifact gets its own unique 256-bit encryption key (DEK)
- Each tier has independent keypairs (compromising warm doesn't expose cold)
- Private keys never exist as files on disk. They live in macOS Keychain (Touch ID), HashiCorp Vault, or cloud KMS. The `file:` key source is deliberately blocked
- Encryption uses only the public key. The private key is retrieved on-demand for recall, used, and zeroed from memory

## Post-quantum because the deadline is already set

NIST published the initial public draft of [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) in November 2024. The proposed timeline: RSA-2048 and P-256 deprecated for new systems by 2030. All RSA and ECC disallowed by 2035.

The risk isn't theoretical. It's "harvest now, decrypt later." An adversary captures your encrypted AI sessions today. Stores them. Waits for a quantum computer. If your key wrapping uses RSA or X25519, Shor's algorithm recovers every DEK regardless of how strong your AES is.

Engram uses ML-KEM-768 (NIST FIPS 203, finalized August 2024) in hybrid mode with X25519 via the `age` encryption tool. Both classical and post-quantum protection simultaneously. This is the same algorithm OpenSSH 10.0 made the default for all key exchange in April 2025.

Why start with legacy crypto and migrate before 2030 when you can start with PQ now?

## What makes Engram different

I looked at existing memory plugins before building this. Here's where they fall short:

**No compression, or flat compression.** Most plugins don't compress at all. The ones that do use a single zstd level. Engram's multi-stage pipeline achieves 4-5x on warm, 8-12x on cold, and 20-50x on frozen. That's the difference between 800 MB of raw sessions and 35 MB of archived ones.

**No encryption.** Session data sits in plaintext. Engram uses post-quantum envelope encryption with per-artifact keys.

**No search without decompression.** If you need to find something in cold storage, you decompress everything. Engram's semantic index searches all tiers without touching the compressed data.

**Locked to one platform.** Most plugins work with one AI assistant. Engram auto-detects Claude, ChatGPT, Cursor, and Copilot. Add any custom path in the config.

**No brain-inspired tiering.** Flat storage treats a session from today the same as one from six months ago. Engram mirrors how biological memory works: recent things stay accessible, old things compress deeper, everything is searchable through the index.

## Try it

Engram is open source: [github.com/qinnovates/engram](https://github.com/qinnovates/engram)

```bash
pip install engram
engram init                           # guided setup, picks your AI assistant locations
engram run --dry-run                  # preview what would be compressed
engram run                            # execute tiering
engram search "that security thing"   # search across all tiers
engram context --query "auth refactor" # get context block for your AI session
```

66 tests. Red-team reviewed by three independent security personas. Anthropic plugin format with marketplace.json. Works as a Claude Code skill invocable as `/engram`.

The plugin compresses your AI's accumulated knowledge so it fits in a context window, encrypts it so it's protected, and indexes it so the right memories surface when you need them. Like how your brain stores and retrieves information, but with post-quantum encryption and columnar compression ratios your hippocampus can only dream about.

---

*Written with AI assistance (Claude). All claims verified by the author.*

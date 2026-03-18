---
name: tiered-memory
description: Manage AI memory artifacts with tiered compression (hot/warm/cold/frozen), semantic search, progressive recall, and optional post-quantum encryption. Use when the user mentions memory management, context optimization, compressing old sessions, searching past conversations, recalling archived memories, encrypting AI data, or managing artifact storage.
allowed-tools: Read, Bash(tiered-memory *), Bash(python3 -m src.cli *), Grep, Glob
user-invocable: true
argument-hint: "[command] [options]"
---

# Tiered Memory Engine

You are managing an AI memory tiering system. When invoked, help the user with memory compression, search, recall, encryption, and context optimization.

## Available Commands

Run commands via the CLI:

```bash
# Initialize config (auto-detects Claude, ChatGPT, Cursor, Copilot artifacts)
tiered-memory init

# Scan for artifacts across all configured AI assistant locations
tiered-memory scan

# Preview tier transitions (safe, no changes)
tiered-memory run --dry-run

# Execute tiering (compress idle artifacts)
tiered-memory run

# Show tier distribution and compression stats
tiered-memory status

# Get context-optimized memory block for AI session injection
tiered-memory context --query "$ARGUMENTS"

# Search indexed memories across all tiers without decompressing
tiered-memory search "$ARGUMENTS"

# Recall a compressed artifact back to hot tier
tiered-memory recall <file-path>

# Set up post-quantum encryption with Touch ID
tiered-memory encrypt-setup
```

## When to Use This Skill

- **User says "compress old memories"** → run `tiered-memory run`
- **User says "search memories for X"** → run `tiered-memory search "X"`
- **User says "what do I have stored?"** → run `tiered-memory status`
- **User says "load context about X"** → run `tiered-memory context --query "X"`
- **User says "recall that old session"** → run `tiered-memory recall <path>`
- **User says "encrypt my memories"** → run `tiered-memory encrypt-setup`
- **User says "how much space am I using?"** → run `tiered-memory status`

## How Tiering Works

Artifacts move through tiers based on age and idle time:

| Tier | When | Compression | Retrieval |
|------|------|-------------|-----------|
| Hot | Active files | None | Instant |
| Warm | 48h old + 24h idle | zstd-3 (~3.2x) | ~10ms |
| Cold | 14d old + 7d idle | zstd-9 (~3.5x) | ~50-500ms |
| Frozen | 90d old + 30d idle | zstd-19 (~3.8x) | 1-10 seconds |

The semantic index (always loaded, never compressed) lets you search all tiers without decompressing. Summaries load first, full content only on demand.

## Post-Quantum Encryption

When encryption is enabled, each artifact gets a unique 256-bit DEK encrypted with the tier's public key via ML-KEM-768 (NIST FIPS 203). Private keys are retrieved on-demand from macOS Keychain (Touch ID), HashiCorp Vault, Cloud KMS, or environment variables. Private key files on disk are deliberately blocked.

## Context Enhancement

The `context` command builds a budget-aware memory block:
1. Hot-tier summaries always included
2. Query-relevant warm/cold/frozen matches surfaced by relevance score
3. Token budget tracked (~4 chars/token) to prevent context overflow
4. Output is plain text any AI assistant can consume

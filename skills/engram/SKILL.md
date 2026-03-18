---
name: engram
description: Manage AI memory artifacts with tiered compression (hot/warm/cold/frozen), semantic search, progressive recall, and optional post-quantum encryption. Use when the user mentions memory management, context optimization, compressing old sessions, searching past conversations, recalling archived memories, encrypting AI data, or managing artifact storage.
allowed-tools: Read, Bash(engram *), Bash(python3 -m src.cli *), Grep, Glob
user-invocable: true
argument-hint: "[command or example name]"
---

# Engram

You are managing an AI memory tiering system. When invoked, help the user with memory compression, search, recall, encryption, and context optimization.

## Examples

When the user runs `/engram examples`, show this list and ask which they'd like to do:

### 1. First-time setup
```bash
# Auto-detect AI assistants, choose tiers, configure thresholds
engram init

# See what's on your system before changing anything
engram scan
engram run --dry-run
```
**What it does:** Discovers all AI session files (Claude, ChatGPT, Cursor, etc.), shows how many artifacts you have, how much disk they use, and what would move to each tier. No files are modified.

### 2. Compress old sessions
```bash
# Move idle artifacts to warm/cold/frozen tiers
engram run

# Check the results
engram status
```
**What it does:** Files older than 48h get minified + compressed (warm, 4-5x). Files older than 14d get boilerplate-stripped + dictionary-compressed (cold, 8-12x). Files older than 90d get converted to columnar Parquet (frozen, 20-50x). Recent files stay untouched.

### 3. Search past conversations
```bash
# Find something across all tiers without decompressing
engram search "authentication refactor"
engram search "that bug we fixed in January"
engram search "TARA threat model"
```
**What it does:** Searches the semantic index (132K+ keywords). Returns matching artifacts with tier, age, summary, and relevance score. No decompression needed — the index is always in memory.

### 4. Load context for this session
```bash
# Get a token-budget-optimized memory block
engram context --query "auth patterns we discussed"
engram context --query "security architecture decisions"
```
**What it does:** Builds a context block from your most relevant memories. Hot summaries load first, then query-relevant warm/cold/frozen matches. Fits within your token budget. Output is plain text you can paste into any AI prompt.

### 5. Recall a frozen artifact
```bash
# Bring a deep-archived session back to hot tier
engram recall ~/.claude/projects/.../session-2025-06-15.jsonl
```
**What it does:** Decompresses (and decrypts if encrypted) a cold/frozen artifact back to hot tier. Cold takes ~500ms. Frozen takes ~5 seconds. The file is fully accessible again. Run `engram run` later to re-tier it when idle.

### 6. Enable post-quantum encryption
```bash
# Install age (PQ encryption tool)
brew install age

# Build the crypto sidecar (handles keys — Python never sees them)
cd engram/sidecar && cargo build --release

# Generate per-tier keypairs stored in Keychain (Touch ID)
engram encrypt-setup
```
**What it does:** Sets up ML-KEM-768 hybrid encryption via a Rust sidecar. Private keys go directly to macOS Keychain — they never exist as files, never enter Python, never appear in terminal output. Every tier gets its own keypair. Every artifact gets its own unique encryption key.

### 7. Set up 2-tier mode (simple)
```bash
# During init, choose 2-tier mode
engram init
# When prompted: "How many storage tiers?" → choose 2
```
**What it does:** Simplified mode with just Hot (recent) and Cold (old, compressed). Fewer moving parts. Good for most users who want compression without complexity.

### 8. Set up 4-tier mode (maximum compression)
```bash
# During init, choose 4-tier mode
engram init
# When prompted: "How many storage tiers?" → choose 4
```
**What it does:** Full pipeline — Hot / Warm (4-5x) / Cold (8-12x) / Frozen (20-50x). Each tier applies different compression strategies. Best disk savings. Recommended for heavy AI users.

### 9. Customize tier thresholds
```bash
# Edit the config directly
cat ~/.engram/config.json
```
**Example thresholds:**
```json
{
  "tier_policy": {
    "hot_to_warm_age_hours": 24,
    "hot_to_warm_idle_hours": 12,
    "warm_to_cold_age_hours": 168,
    "warm_to_cold_idle_hours": 72,
    "cold_to_frozen_age_hours": 720,
    "cold_to_frozen_idle_hours": 336
  }
}
```
**What it does:** Moves artifacts faster (24h instead of 48h to warm) or slower. Set any threshold to match your workflow. Aggressive for disk savings, conservative for fast access.

### 10. Enable most secure mode (encrypt everything including hot)
```bash
# During init, enable encryption, then choose "most secure"
engram init
# Enable PQ encryption? → yes
# Enable most secure mode (encrypt all tiers including hot)? → yes
```
**What it does:** Encrypts every file at rest, including active session files in hot tier. Requires Touch ID on every file read. Maximum security — no plaintext on disk at any tier. Slower reads but nothing is ever unprotected.

### 11. Check what you're wasting
```bash
engram status
```
```
Total artifacts:   4,564
  Hot:             4,237
  Warm:            41
  Cold:            286
  Frozen:          0
Total original:    2.6 GB
Total compressed:  222 MB
Overall ratio:     11.62x
Space saved:       1.6 GB
Indexed:           132,081 keywords
```

### 12. Verify data integrity
```bash
# Check SHA-256 hashes of all tracked artifacts
engram verify
```
**What it does:** Computes the current hash of every tracked artifact and compares against the stored hash. Reports passed, failed, and skipped (no hash stored). Failed = file was modified or corrupted since registration.

### 13. Rebuild the search index
```bash
# If the index is corrupted or you want a fresh start
engram reindex
```
**What it does:** Deletes the semantic index and re-scans all artifacts. Re-extracts keywords and summaries. Use after moving files, changing scan targets, or recovering from corruption.

## Available Commands

| Command | What |
|---------|------|
| `engram init` | Guided setup (2-tier or 4-tier, encryption choice) |
| `engram scan` | Discover artifacts |
| `engram run` | Execute tier transitions |
| `engram run --dry-run` | Preview without changes |
| `engram status` | Tier distribution and stats |
| `engram search <query>` | Search all tiers |
| `engram context --query <q>` | Budget-optimized context block |
| `engram recall <path>` | Decompress to hot |
| `engram reindex` | Rebuild semantic index |
| `engram verify` | SHA-256 integrity check |
| `engram encrypt-setup` | Configure encryption |

# Governance Architecture (SIEMPLE-AI Integration)

> Myelin8 v2.0.0 integrates SIEMPLE-AI's layered context orchestration as its governance layer. This directory contains the specification, schemas, and design rationale.

## Why This Exists

Myelin8 v1.0 encrypted everything, including `~/.claude/`. Claude's Read tool couldn't decrypt. Memory was invisible to the consumer. The lesson: **build the integration layer before the security layer.**

SIEMPLE-AI provides the governance model that sits between Myelin8's storage engine and Claude Code. It ensures:

1. **Every write is validated** (schema, policy, PII scan, conflict detection, audit)
2. **Every read is transparent** (Claude talks to MCP, never touches compressed files)
3. **Context is assembled, not dumped** (top-5 facts by relevance, not all 500)
4. **Security constraints are enforced by hooks, not memory** (CLAUDE.md is advisory)

## Architecture

```
Claude Code ──MCP──> myelin8-rs ──subprocess──> Python governance
                         |                           |
                    tantivy + Parquet          schemas + policy + audit
                    (storage engine)          (SIEMPLE-AI governance)
```

**Ownership boundaries:**

| Component | Owns | Does NOT Own |
|-----------|------|-------------|
| SIEMPLE-AI governance | Schema validation, write policy, context assembly, audit | Storage, compression, search, encryption |
| Myelin8 engine | Tiered storage, compression, Parquet, tantivy, Merkle, encryption | Write policy, confidence scoring, layer precedence |
| MCP server | JSON-RPC interface, tool routing | Governance decisions (delegates to Python) |

## The Five Layers (Three Active in v2.0.0)

SIEMPLE-AI defines 5 configuration layers. For single-user personal use, Myelin8 activates 3:

| Layer | Status | Purpose |
|-------|--------|---------|
| Layer 1: System | **Active** | Immutable safety constraints, tool policies. Cannot be overridden. |
| Layer 2: App/Domain | Deferred | Use-case defaults (research vs SOC). Reserved for multi-tenant. |
| Layer 3: Environment | Deferred | dev/stage/prod overrides. Reserved for deployment. |
| Layer 4: User | **Active** | Durable preferences, goals, exclusions. |
| Layer 5: Session | **Active** | Ephemeral state, 72h TTL, pending writes. |

Layers 2 and 3 are defined in schemas but not loaded at runtime. They exist for future expansion.

## Write Path

```
1. Claude calls memory_ingest_governed MCP tool
2. Rust MCP server calls Python governance via subprocess
3. WritePolicy evaluates:
   - Credential blocklist (reject + alert)
   - PII blocklist (reject + warn)
   - Blocked key prefixes (reject — security belongs in Layer 1)
   - Confidence ceiling (inferred capped at 0.8)
   - Source routing (explicit=approve, inferred=pending, imported=approve)
4. SchemaValidator checks against fact.schema.yaml or episode.schema.yaml
5. Conflict detector scans for same-key contradictions
6. Audit logger writes to memory_writes.jsonl (metadata only, never content)
7. If approved: Rust indexes in tantivy + writes to hot/ as plaintext JSON
```

## Read Path

```
1. Claude calls memory_search MCP tool
2. tantivy FTS returns ranked summaries (200 tokens each, not full 10K+)
3. Claude picks which artifacts to recall
4. memory_recall returns full content from hot/ (plaintext) or Parquet (decompress)
5. SHA-256 verify against stored hash
```

## Context Assembly

```
1. Claude calls memory_context MCP tool
2. Python ContextAssembler:
   a. Clean up stale sessions (lazy GC)
   b. Load Layer 1 (system defaults — immutable fields locked)
   c. Load Layer 4 (user preferences — overrides system, except immutable)
   d. Load Layer 5 (session state — if session_id provided and not expired)
   e. Retrieve top-5 facts by confidence (skip expired, skip high-sensitivity)
   f. Retrieve top-3 episodes by date
   g. Enforce token budget (default 32K tokens)
3. Return assembled context block
```

## Key Design Decisions

| Decision | Rationale | Source |
|----------|-----------|--------|
| Subprocess bridge, not PyO3 | Isolation (governance bug can't crash MCP), clean build, proven at Splunk scale | Quorum panel, SIEM Practitioner |
| 3 active layers, not 5 | Layers 2-3 are dead weight for single-user | Quorum panel, adversarial review |
| Retrieve top-5, not inject all | Splunk pattern: search the index, don't dump the raw data | SIEMPLE-AI P1 |
| CLAUDE.md advisory, hooks enforced | CLAUDE.md degrades with context; hooks run outside the window | SIEMPLE-AI core principle |
| Parquet is source of truth | Indexed, searchable, integrity-verified. JSONL is for human editing | Quorum panel consensus |
| Encryption deferred to v2.1.0 | Hot tier must stay plaintext for Read tool. MCP-mediated decryption needs own threat model | Security Engineer, adversarial |

## Documents in This Directory

| File | What It Covers |
|------|---------------|
| [LAYERED-CONTEXT.md](LAYERED-CONTEXT.md) | Full 5-layer architecture specification |
| [MEMORY-TYPES.md](MEMORY-TYPES.md) | Semantic facts, episodic events, session state, procedural memory |
| [PRECEDENCE.md](PRECEDENCE.md) | Layer merge algorithm with worked examples |
| [ANTI-PATTERNS.md](ANTI-PATTERNS.md) | What NOT to do (god memory files, silent writes, no TTL, etc.) |
| [schemas/fact.schema.yaml](schemas/fact.schema.yaml) | JSON Schema for semantic memory facts |
| [schemas/episode.schema.yaml](schemas/episode.schema.yaml) | JSON Schema for episodic memory events |
| [schemas/memory-write-policy.yaml](schemas/memory-write-policy.yaml) | Write rules: auto-write, pending, blocked |
| [schemas/artifact-mapping.yaml](schemas/artifact-mapping.yaml) | Parquet column ↔ SIEMPLE-AI field mapping |

## Origin

This governance architecture was originally developed as [SIEMPLE-AI](https://github.com/qinnovates/SIEMPLE-AI), a standalone reference implementation for layered context orchestration. The core insight: every production SIEM follows the same configuration model (global → app → env → tenant → user → runtime). AI agents need the exact same architecture.

SIEMPLE-AI was integrated into Myelin8 in v2.0.0 because the two projects solve complementary halves of the same problem: SIEMPLE-AI governs *what* gets stored and retrieved; Myelin8 handles *how* it's stored and searched.

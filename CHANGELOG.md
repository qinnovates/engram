# Changelog

## 2026-04-02 — SIEMPLE-AI Governance Integration (v2.0.0-alpha)

Integrates SIEMPLE-AI's 5-layer context orchestration into Myelin8's storage engine. Fixes the core issue where compression/encryption broke Claude's ability to read memory by adding a governance layer between storage and consumer.

### New: Governance Pipeline (Python)
- `src/governance.py` — Write gate orchestrator. Every memory write goes through schema validation → write policy → PII/credential scan → conflict detection → audit logging
- `src/write_policy.py` — Enforces SIEMPLE-AI memory-write-policy.yaml: explicit writes auto-approve, inferred writes pend, PII/credentials/security keys blocked
- `src/schema_validator.py` — Validates facts/episodes against SIEMPLE-AI YAML schemas (graceful fallback if pyyaml/jsonschema not installed)
- `src/context_assembler.py` — 3-layer merge (System + User + Session), top-N fact retrieval, token budget enforcement, expired/high-sensitivity filtering, stale session cleanup (lazy GC)

### New: MCP Tools (Rust)
- `memory_ingest_governed` — Write-gated ingest through governance pipeline via subprocess bridge. Returns ingested/pending/rejected with audit trail
- `memory_context` — Assembles context block from layers + relevant memories within token budget

### Changed: Artifact Schema (Rust)
- Extended `Artifact` struct with 8 governance fields: namespace, memory_type, confidence, source_provenance, sensitivity, tags, expires_at, session_id
- Extended tantivy index with 7 new searchable fields
- All new fields have serde defaults — backward-compatible with v1.2.0 data

### New: Audit Trail
- Every governance decision (approve/pending/reject) logged to `~/.myelin8/audit/memory_writes.jsonl`
- Audit entries contain metadata only — NEVER content

### New: Session Lifecycle
- Stale sessions (>72h) cleaned up at next context assembly
- Unconfirmed pending writes discarded on session expiry

### Tests
- 41 new tests (26 governance + 15 context assembler)
- 178 total passing, 40 skipped, zero regression from v1.2.0

### Dependencies
- New optional: `pyyaml>=6.0`, `jsonschema>=4.17` under `[governance]` extra

## 2026-03-19 — Security Hardening

Six patches applied across 4 files. All found via automated red team scan and validated by purple team review. 110 tests passing.

### vault.py

- **Path canonicalization (CWE-22):** Added `Path.resolve()` in `encrypt()` and `decrypt()` before sending paths to the sidecar. Prevents `../` traversal sequences from reaching the Rust binary.

- **Tier allowlist (CWE-20):** Added `_VALID_TIERS` frozenset and validation in `_validate_input()`. Rejects any tier value outside `{hot, warm, cold, frozen, index}`, closing a protocol injection vector via crafted tier strings.

- **Context manager (CWE-404):** Added `__enter__`/`__exit__` to `VaultClient`. Ensures deterministic sidecar process cleanup instead of relying on `__del__`, which CPython does not guarantee to call.

### index_crypto.py

- **Atexit re-lock (CWE-377):** `unlock()` now registers an `atexit` handler that calls `lock()` on process exit. Reduces the plaintext exposure window — if the process exits without explicit `lock()`, the index is re-encrypted automatically. Does not cover `SIGKILL`/OOM (inherent OS limitation).

### pipeline.py

- **Temp file permissions (CWE-732):** Changed all three compression paths (`compress_warm`, `compress_cold`, `compress_frozen` fallback) to call `os.fchmod(fd, 0o600)` on the file descriptor *before* writing content. Previously, `os.chmod()` was called *after* write, leaving a brief window where the file could be readable depending on umask.

### engine.py

- **Recall error path cleanup (CWE-459):** Decrypted intermediate files are now deleted on decompression failure and integrity check failure during `recall()`. Previously, a failed decompression left the decrypted `.zst` file on disk permanently.

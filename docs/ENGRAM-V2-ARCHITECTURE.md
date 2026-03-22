# Engram v2 Architecture — Brain-Informed Real-Time AI Memory

*Drafted 2026-03-21. Kevin Qi + Claude Opus 4.6.*
*Reviewed by 5-expert quorum (neuroscientist, distributed systems, AI agent, security, devil's advocate). Revised based on consensus.*

## The Problem With v1

Engram v1 models the brain's storage tiers well. It models retrieval poorly.

When you remember something, your brain doesn't decompress a file. It reconstructs from cues — the gist arrives instantly, details fill in on demand, and related memories surface automatically. v1 makes Claude do the file system version: search → decompress whole artifact → read. All-or-nothing.

Three real problems agents hit with v1:
1. **Recall is all-or-nothing.** Decompress 50KB to find the one 200-byte decision you need.
2. **No related context.** Recall one artifact, get nothing about related artifacts. Claude has to search separately for each connection.
3. **No integrity trust.** Claude gets a summary from the index but has no proof it's authentic. Could be stale or corrupted.

---

## What the Brain Does (and Where the Analogy Stops)

The hippocampus doesn't store memories. It stores pointers — pattern-separated index codes that reconstruct the original experience from fragments across the neocortex (Teyler & DiScenna 1986).

| Brain Process | Engram v2 |
|---|---|
| Hippocampal pattern match | Semantic search + HNSW |
| Pattern completion (gist first) | Verified summary → selective section recall |
| Spreading activation | Activation graph auto-returns related artifacts |
| Priming | Session-topic analysis pre-warms search index |
| Reconsolidation | Keyword update on access (deferred — needs bounds) |

These are **design analogies** that inform architecture decisions. They are not algorithmic equivalences. The brain reconstructs from noisy distributed traces via attractor dynamics. Engram decompresses structured data from deterministic storage. The functional outcome (partial cue → useful result) is shared. The mechanism is completely different.

What the brain does that Engram v2 still doesn't model:
- **Interference** — competing memories actively degrade each other. Engram treats artifacts as independent.
- **Schema extraction** — sleep consolidation abstracts patterns over time, not just compresses data.
- **State-dependent retrieval** — emotional and environmental context modulates recall strength.
- **Prospective memory** — goal-directed retrieval triggered by environmental cues.

---

## Architecture (Ordered by Implementation Priority)

### 1. Merkle-Verified Summaries

**Status: BUILD FIRST. Low cost, Rust sidecar already exists.**

**Problem:** Claude gets a summary from the semantic index but has no proof it accurately represents the compressed artifact. The summary could be stale, corrupted, or fabricated.

**Solution:** Every summary in the semantic index gets its own Merkle leaf, linked to the artifact's content leaf. Claude verifies in <1ms via the Rust sidecar.

```
Merkle Tree:
          Root (SHA3-256)
         /    \
   Content     Summaries
   /    \      /      \
  Art1  Art2  Sum1    Sum2
               ↓       ↓
           (linked to Art1, Art2)
```

Claude trusts the summary. No decompression needed for most recall operations. Proof verification is constant-time in Rust.

**Implementation:**
- [ ] Add summary hash to `ArtifactSummary` dataclass in `context.py`
- [ ] On `engram scan`: hash each summary, add as Merkle leaf via sidecar
- [ ] On `engram recall` / `engram search`: return Merkle proof dict alongside summary
- [ ] Claude hook: verify proof before injecting recalled content into prompt

### 2. Selective Section Decompression

**Status: BUILD SECOND. Simple approach first, frame-per-section deferred.**

**Problem:** Cold/frozen recall is all-or-nothing. Decompress 50KB to find one section.

**Solution (simple, validated by quorum):** Decompress the full artifact, split on section headers, return only the requested section. No compression format changes needed.

```bash
# v1: all or nothing
engram recall ~/.claude/sessions/auth-refactor.jsonl  # returns 50KB

# v2: selective
engram recall ~/.claude/sessions/auth-refactor.jsonl --section decisions  # returns 2KB
engram recall ~/.claude/sessions/auth-refactor.jsonl --section code       # returns 5KB
```

**Why not frame-per-section zstd:**
The quorum's distributed systems engineer identified three problems:
1. Compression ratio degrades 30-40% when sections are compressed independently (dictionary resets at frame boundaries)
2. Python-zstandard doesn't expose the `ZSTD_seekable_*` API for seekable frame decompression
3. Would require a custom container format or Rust sidecar extensions

Simple post-decompression section splitting gets 80% of the value with 10% of the engineering. If real-world latency measurements prove this isn't fast enough, prototype the frame approach then.

**Section identification:**
```python
# Standard section headers in Engram artifacts
SECTION_PATTERNS = {
    "context": r"^##?\s*(Context|Background)",
    "decisions": r"^##?\s*(Decision|Outcome|Conclusion)",
    "code": r"^##?\s*(Code|Implementation|Changes)",
    "questions": r"^##?\s*(Question|Open|TODO|Next)",
    "discussion": r"^##?\s*(Discussion|Conversation|Exchange)",
}
```

**Implementation:**
- [ ] Add `--section` flag to `engram recall` CLI
- [ ] Add `section_extract(content: str, section: str) -> str` utility
- [ ] Return Merkle proof for the full artifact (section is a substring, artifact is verified)

### 3. Activation Graph (Simple Version)

**Status: BUILD THIRD. Co-occurrence first, weighted multi-signal later.**

**Problem:** Recalling one artifact gives no information about related artifacts. Claude has to search separately for each connection.

**Solution (phased):**

**Phase A — co-occurrence logging (build now):**
When artifacts are recalled in the same session, record an edge. When artifacts share 3+ keywords, record an edge. Return top-3 related summaries with every recall.

```python
result = engram.recall("auth refactor")
# Returns:
#   .content = the recalled section
#   .related = [
#     {path: "api-security.jsonl", summary: "...", edge: "co-recalled 3x"},
#     {path: "db-migration.jsonl", summary: "...", edge: "shared: auth, token, middleware"},
#   ]
#   .proof = <merkle proof>
```

**Phase B — weighted multi-signal (build when data exists):**
Add embedding cosine similarity and temporal proximity as edge weights. Requires tuning — defer until co-occurrence data reveals what "related" actually means in practice.

**Storage:** SQLite, not JSON. At 10K artifacts with ~10 edges each, a 100K-edge adjacency list needs efficient lookup and incremental updates. JSON parse of 10MB on every recall is a bottleneck.

```sql
CREATE TABLE edges (
    source_hash TEXT,
    target_hash TEXT,
    weight REAL,
    edge_type TEXT,  -- 'co-recalled', 'shared-keywords', 'temporal', 'embedding'
    last_updated REAL,
    PRIMARY KEY (source_hash, target_hash)
);
CREATE INDEX idx_source ON edges(source_hash);
```

**Implementation:**
- [ ] Create `activation.py` with SQLite-backed edge store
- [ ] Record co-occurrence edges on `engram recall`
- [ ] Record keyword overlap edges on `engram scan`
- [ ] Return top-3 related summaries in recall response
- [ ] Prune edges older than 90 days or below weight threshold

**Quorum security note:** The activation graph encodes artifact relationships. Even encrypted, file size reveals edge count. For high-security deployments, pad the SQLite database to a fixed size.

---

## Deferred (Measure Before Building)

### 4. Predictive Pre-Fetch

**Status: DEFERRED. Measure actual cold/frozen recall latency first.**

The quorum's devil's advocate raised a valid point: LLM inference takes 1-10 seconds. A 500ms cold recall at session start is not a meaningful bottleneck in practice. Pre-fetching adds complexity and breaks least-privilege by eagerly decrypting cold tier content.

**Build condition:** If real-world measurement shows cold/frozen recall adds >1s perceived latency in agent sessions, implement pre-fetch with an explicit "unlock session" ceremony for encrypted tiers.

### 5. Reconsolidation (Update on Access)

**Status: DEFERRED. Needs three problems solved first.**

The concept (re-indexing recalled artifacts with current context so they're easier to find in future similar contexts) is sound. But:

1. **Semantic drift.** Blending embeddings (0.7 original + 0.3 current) over many recalls causes the embedding to drift from the artifact's actual content. Needs a maximum reconsolidation count or decay model.
2. **Metadata side channel.** Re-indexed keywords encode information about the CURRENT session into HISTORICAL artifact metadata. An adversary accessing the index can infer recent activity by examining which old artifacts have been reconsolidated.
3. **Concurrent access.** Two sessions reconsolidating the same artifact simultaneously creates a race condition on the index.

**Build condition:** When the activation graph generates enough data to demonstrate that old artifacts are genuinely unfindable with current search, and after concurrent access is solved.

---

## Missing Sections (Identified by Quorum)

### Concurrent Access

Two Claude Code sessions (or subagents) running simultaneously is common. Both hit Engram's metadata registry, semantic index, and activation graph.

**Current v1 state:** `atomic_write_text()` prevents file corruption on write. But no file locking means two concurrent `engram run` operations can produce inconsistent state.

**v2 requirement:** SQLite for the activation graph solves concurrent reads. For writes: either file-level locking (fcntl on Unix) or migrate the metadata registry to SQLite as well. This is a prerequisite for the activation graph, not an afterthought.

### Why Engram Remains Valuable When Context Windows Grow

Context windows will hit 10M tokens. That makes raw capacity less scarce. It does NOT solve:

1. **Finding the right context.** 10M tokens of everything is worse than 32K tokens of the right thing. Semantic search, keyword index, and activation graph are more valuable when the haystack is bigger.
2. **Cost.** Loading 40MB of text into every prompt is expensive. Engram's tiered compression reduces what needs to be loaded. Even at 10M tokens, you don't want to pay for 10M on every API call.
3. **Integrity.** A 10M context window doesn't tell you if the content is real. Merkle verification does. This becomes MORE important as context gets bigger — more data means more surface area for hallucination.
4. **Privacy.** A bigger window means more sensitive data loaded per prompt. Engram's tier-gated encryption ensures only relevant, authorized content enters the context.

Engram's value shifts from "fit context into a small window" to "find, verify, and secure context within a large window." The compression becomes less important. The search, integrity, and privacy become more important.

---

## Implementation Phases

### Phase 1 (Build Now)
- [ ] Merkle-verified summaries (summary leaf + proof in recall response)
- [ ] Selective section decompression (`engram recall --section decisions`)
- [ ] Co-occurrence edge logging in SQLite
- [ ] Related artifacts returned with recall (top-3)
- [ ] Concurrent access: file locking for metadata writes

### Phase 2 (After Phase 1 Deployed + Measured)
- [ ] Weighted activation graph (embedding similarity + temporal edges)
- [ ] Latency measurement harness for cold/frozen recall in real sessions
- [ ] Predictive pre-fetch (only if measurements justify it)

### Phase 3 (After Concurrent Access Solved)
- [ ] Reconsolidation with drift bounds and side channel isolation
- [ ] Frame-per-section compression (only if section splitting latency is proven insufficient)
- [ ] Graph padding for high-security deployments

---

## Crypto Model (Unchanged)

All v2 features maintain the existing PQC security model:

| Layer | Algorithm | NIST Standard |
|-------|-----------|---------------|
| Tree hashes | SHA3-256 | FIPS 202 |
| Root seal | HMAC-SHA3-256 | FIPS 198-1 + FIPS 202 |
| Seal key | ML-KEM-768 + HKDF | FIPS 203 + SP 800-56C |
| Artifact encryption | AES-256-GCM | FIPS 197 + SP 800-38D |
| Key encapsulation | ML-KEM-768 + X25519 hybrid | FIPS 203 |
| All crypto operations | Rust sidecar | mlocked, zero core dumps |

---

## Quorum Review Summary

*5-expert review conducted 2026-03-21.*

| Feature | Neuroscientist | Dist. Systems | Agent Dev | Security | Devil's Advocate | Consensus |
|---------|:-:|:-:|:-:|:-:|:-:|---|
| Merkle summaries | APPROVE | APPROVE | APPROVE | APPROVE | APPROVE | **BUILD** |
| Section decompression | APPROVE | REVISE | REVISE | REVISE | REJECT complex | **BUILD (simple)** |
| Activation graph | REVISE | REVISE | APPROVE | REVISE | REVISE | **BUILD (co-occurrence first)** |
| Predictive pre-fetch | APPROVE | APPROVE | REVISE | REVISE | REJECT | **DEFER (measure first)** |
| Reconsolidation | REVISE | APPROVE | APPROVE | REVISE | REJECT | **DEFER (solve 3 problems)** |

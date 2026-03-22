# Merkle-as-Index: Technical Specification

*2026-03-21. Based on measured bottlenecks, not theoretical analysis.*

## Measured Bottlenecks (4,560 artifacts)

| Operation | Current | With Merkle-Index | Improvement |
|---|---|---|---|
| Load semantic index | 22.9ms (5.3MB JSON parse) | 0ms (in-memory, loaded once) | Eliminated |
| Load artifact registry | 16.7ms (3MB JSON parse) | 0ms (in-memory, loaded once) | Eliminated |
| Keyword search | 0.03ms | 0.01ms (Rust inverted index) | 3x |
| Get summary + metadata | ~1ms (dict lookup) | 0.01ms (leaf payload) | 100x |
| Integrity verification | 0.03ms (separate step) | 0ms (free with lookup) | Free |
| **Total (before decompression)** | **~40ms** | **~0.05ms** | **~800x** |

The improvement doesn't come from Merkle math. It comes from eliminating 8MB of JSON parsing on every invocation by holding everything in a Rust process that stays alive.

## Architecture

```
BEFORE (v1):
  Every engram call:
    Python starts → parse 5.3MB JSON → parse 3MB JSON → search → done
    (40ms tax on every invocation, even for a simple search)

AFTER (Merkle-index):
  Sidecar starts once (session lifetime):
    Load tree + index into memory → ready
  Every engram call:
    Python → sidecar IPC (0.15ms round-trip) → lookup + proof → return
    (0.2ms total, including IPC overhead)
```

### Sidecar Data Structures (Rust, in-memory)

```rust
struct MerkleIndex {
    // Merkle tree (existing)
    tree: MerkleTree,

    // Content-addressed leaf payloads
    // Hash → rich metadata (not just a hash anymore)
    payloads: HashMap<[u8; 32], LeafPayload>,

    // Inverted keyword index for search
    // keyword → set of content hashes
    keyword_index: HashMap<String, HashSet<[u8; 32]>>,

    // Tier index for filtered queries
    // tier → set of content hashes
    tier_index: HashMap<String, HashSet<[u8; 32]>>,
}

struct LeafPayload {
    content_hash: [u8; 32],      // SHA3-256 of original content
    summary: String,              // 1-2 sentence summary
    keywords: Vec<String>,        // searchable keywords
    tier: String,                 // hot | warm | cold | frozen
    path: String,                 // original file path
    compressed_path: String,      // where the compressed file lives
    byte_size: u64,               // compressed size
    created_at: f64,              // unix timestamp
    last_accessed: f64,
    section_headers: Vec<String>, // ["Context", "Decisions", "Code"]
}
```

### New Sidecar Protocol Commands

```
INDEX_LOAD <json_path>           → OK <count> | ERROR
  Load semantic index + registry into memory. Called once at session start.

INDEX_SEARCH <query>             → OK <json_array_of_results>
  Keyword search against inverted index. Returns summaries + proofs.
  Each result includes Merkle proof (verified by construction).

INDEX_LOOKUP <content_hash>      → OK <json_payload> | ERROR
  Direct hash lookup. O(1). Returns full leaf payload + Merkle proof.

INDEX_RELATED <content_hash> <n> → OK <json_array>
  Return top-N related artifacts by co-occurrence/keyword overlap.

INDEX_STATS                      → OK <json>
  Artifact count per tier, total size, keyword count, tree depth.
```

### Memory Footprint

Per artifact in the sidecar:
- Leaf payload: ~500 bytes average (summary + keywords + metadata)
- Inverted index entry: ~200 bytes (keywords → hash pointers)
- Merkle leaf: 32 bytes

At 4,560 artifacts: ~500 * 4,560 + 200 * 4,560 * 10 + 32 * 4,560 = ~11.5MB
At 10,000 artifacts: ~25MB
At 50,000 artifacts: ~125MB

Acceptable for a long-running sidecar process. The current JSON files are already 8MB for 4,560 artifacts.

### What Changes for Claude

```
BEFORE:
  Claude hook calls: python3 -m engram search "auth"
    → Python boots, parses 8MB JSON, searches, exits
    → 40ms + Python startup (~200ms cold, ~50ms warm)

AFTER:
  Claude hook calls: python3 -m engram search "auth"
    → Python sends "INDEX_SEARCH auth" to running sidecar
    → Sidecar returns results + proofs in 0.2ms
    → Python formats and returns
    → Total: 0.5ms (sidecar already running)
```

Python startup is still ~50ms on warm invocation. The real optimization is keeping the sidecar alive for the session duration (it already does this for encryption) and having it hold the full index. Python becomes a thin CLI wrapper over sidecar IPC.

### What Changes for Encryption

Nothing. The leaf payloads contain summaries and metadata — not the encrypted content itself. The actual artifact data stays on disk, encrypted with AES-256-GCM. When Claude needs full content (not just the summary), the existing decrypt → decompress path runs. The Merkle-index accelerates the SEARCH, not the DECRYPTION.

```
Search path (accelerated):
  INDEX_SEARCH → summary + proof → Claude reads summary → done (80% of cases)

Full recall path (unchanged):
  INDEX_SEARCH → summary not enough → DECRYPT + DECOMPRESS → full content
```

### What This Means for Merkle Integrity

Every search result comes with a Merkle proof for free. The proof is generated at lookup time because the tree is in memory — zero additional cost. Claude never gets an unverified summary.

The Merkle tree becomes three things simultaneously:
1. **Integrity verification** — hash chain proves no tampering
2. **Content-addressed index** — hash → payload lookup in O(1)
3. **Search accelerator** — inverted keyword index keyed to the same hashes

One data structure. Three functions. All in the Rust trust boundary.

### Implementation Steps

1. [ ] Define `LeafPayload` struct in Rust (sidecar/src/merkle.rs)
2. [ ] Add `HashMap<[u8; 32], LeafPayload>` to `MerkleTree` struct
3. [ ] Add inverted keyword index (`HashMap<String, HashSet<[u8; 32]>>`)
4. [ ] New protocol: `INDEX_LOAD` — parse semantic-index.json + artifact-registry.json into memory
5. [ ] New protocol: `INDEX_SEARCH` — keyword lookup → return matching payloads + proofs
6. [ ] New protocol: `INDEX_LOOKUP` — hash lookup → return payload + proof
7. [ ] Update `vault.py` VaultClient with `index_search()`, `index_lookup()` methods
8. [ ] Update `cli.py` — `engram search` routes through sidecar when available
9. [ ] SessionStart hook: call `INDEX_LOAD` once to warm the sidecar
10. [ ] Benchmark: before/after latency for search across 4,560 artifacts

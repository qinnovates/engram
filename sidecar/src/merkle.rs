//! Merkle-Index: PQC-hardened integrity verification AND search acceleration.
//!
//! This module serves triple duty:
//!   1. INTEGRITY — SHA3-256 Merkle tree proves no artifact has been tampered with
//!   2. INDEX — LeafPayload stores summaries + metadata for instant lookup
//!   3. SEARCH — inverted keyword index for sub-millisecond keyword queries
//!
//! Hash: SHA3-256 (NIST FIPS 202), 128-bit post-quantum collision resistance
//! Domain separation: leaf = SHA3-256(0x00 || data), node = SHA3-256(0x01 || L || R)
//! Root seal: HMAC-SHA3-256(root, HKDF-derived key) — key derived INSIDE sidecar
//! Manifest: SHA3-256 of the loaded JSON — detects tampering before index load
//!
//! Version: 1 (stored in serialized tree, enables future hash algorithm migration)

use sha3::{Sha3_256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use std::collections::{HashMap, HashSet};

type HmacSha3 = Hmac<Sha3_256>;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const TREE_VERSION: u8 = 1;

// ── Size limits (Finding #9: prevent DoS via oversized INDEX_LOAD) ──
const MAX_ARTIFACTS: usize = 100_000;
const MAX_KEYWORDS_PER_ARTIFACT: usize = 100;
const MAX_SUMMARY_BYTES: usize = 4_096;
const MAX_KEYWORD_BYTES: usize = 128;

// ── Seal key derivation context (Finding #2: derive internally, not from Python) ──
const SEAL_HKDF_INFO: &[u8] = b"engram-merkle-seal-v1";
const MANIFEST_HKDF_INFO: &[u8] = b"engram-manifest-sign-v1";

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Constant-time comparison (prevents timing side channels)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derive a key for HMAC sealing or manifest signing from raw key material.
/// Uses HKDF-SHA3-256 so the seal key never leaves the sidecar.
fn derive_key(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).expect("HKDF expand failed");
    key
}

// ── Leaf Payload (the index entry per artifact) ──

#[derive(Clone)]
pub struct LeafPayload {
    pub content_hash: [u8; 32],
    pub summary: String,
    pub keywords: Vec<String>,
    pub tier: String,
    pub path: String,
    pub created_at: f64,
    pub last_accessed: f64,
    pub section_headers: Vec<String>,
}

// ── Search Result ──

pub struct SearchResult {
    pub payload: LeafPayload,
    pub leaf_index: usize,
    pub proof: MerkleProof,
}

// ── Merkle-Index ──

pub struct MerkleIndex {
    // Merkle tree
    leaves: Vec<[u8; 32]>,
    layers: Vec<Vec<[u8; 32]>>,
    dirty: bool,
    root_seal: Option<[u8; 32]>,

    // Index: content hash → payload
    payloads: HashMap<[u8; 32], (usize, LeafPayload)>,  // hash → (leaf_index, payload)

    // Inverted keyword index: keyword → set of content hashes
    keyword_index: HashMap<String, HashSet<[u8; 32]>>,

    // Tier index: tier → set of content hashes
    tier_index: HashMap<String, HashSet<[u8; 32]>>,

    // Manifest hash of the loaded JSON (Finding #15: detect poisoning)
    loaded_manifest: Option<[u8; 32]>,

    // Seal key (derived internally from Keychain material, never from Python)
    seal_key: Option<[u8; 32]>,
}

impl MerkleIndex {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            layers: Vec::new(),
            dirty: true,
            root_seal: None,
            payloads: HashMap::new(),
            keyword_index: HashMap::new(),
            tier_index: HashMap::new(),
            loaded_manifest: None,
            seal_key: None,
        }
    }

    // ── Seal key management (Finding #2) ──

    /// Set the seal key material. The sidecar derives the actual HMAC key via HKDF.
    /// Called once at startup with key material from Keychain.
    pub fn set_seal_key_material(&mut self, ikm: &[u8]) {
        self.seal_key = Some(derive_key(ikm, SEAL_HKDF_INFO));
    }

    // ── Add ──

    pub fn add_hash(&mut self, hash: &[u8; 32]) -> usize {
        let h = hash_leaf(hash);
        self.leaves.push(h);
        self.dirty = true;
        self.root_seal = None;
        self.leaves.len() - 1
    }

    pub fn add_hex(&mut self, hex: &str) -> Result<usize, String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err("Expected 64-char hex (32 bytes)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(self.add_hash(&arr))
    }

    /// Add an artifact with full payload (the index entry).
    pub fn add_artifact(&mut self, payload: LeafPayload) -> Result<usize, String> {
        // Size limits (Finding #9)
        if self.payloads.len() >= MAX_ARTIFACTS {
            return Err(format!("Max artifact count ({}) reached", MAX_ARTIFACTS));
        }
        if payload.summary.len() > MAX_SUMMARY_BYTES {
            return Err(format!("Summary exceeds {} bytes", MAX_SUMMARY_BYTES));
        }
        if payload.keywords.len() > MAX_KEYWORDS_PER_ARTIFACT {
            return Err(format!("Too many keywords (max {})", MAX_KEYWORDS_PER_ARTIFACT));
        }

        let leaf_index = self.add_hash(&payload.content_hash);

        // Index keywords (Finding #17: keywords are stored as-is, SQL uses parameterized queries)
        for kw in &payload.keywords {
            if kw.len() > MAX_KEYWORD_BYTES { continue; } // Skip oversized keywords
            let kw_lower = kw.to_lowercase();
            self.keyword_index
                .entry(kw_lower)
                .or_default()
                .insert(payload.content_hash);
        }

        // Index tier
        self.tier_index
            .entry(payload.tier.clone())
            .or_default()
            .insert(payload.content_hash);

        // Store payload
        self.payloads.insert(payload.content_hash, (leaf_index, payload));

        Ok(leaf_index)
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn artifact_count(&self) -> usize {
        self.payloads.len()
    }

    // ── Search (the fast path — no disk, no decompression) ──

    /// Keyword search with scoring. Returns matching payloads ranked by relevance.
    /// Score = (matching terms / total terms). Union, not intersection.
    pub fn search(&mut self, query: &str) -> Vec<SearchResult> {
        let terms: Vec<String> = query.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if terms.is_empty() {
            return Vec::new();
        }

        // Score each artifact by how many query terms match its keywords
        let mut scores: HashMap<[u8; 32], f64> = HashMap::new();
        let term_count = terms.len() as f64;

        for term in &terms {
            // Substring match across all keywords
            for (kw, hashes) in &self.keyword_index {
                if kw.contains(term.as_str()) {
                    for hash in hashes {
                        *scores.entry(*hash).or_insert(0.0) += 1.0 / term_count;
                    }
                }
            }
        }

        // Sort by score descending, take top 20
        let mut scored: Vec<([u8; 32], f64)> = scores.into_iter().collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(20);

        let hashes: HashSet<[u8; 32]> = scored.iter().map(|(h, _)| *h).collect();

        // Collect matches first (avoids borrow conflict with self.proof)
        let matches: Vec<(usize, LeafPayload)> = hashes.iter()
            .filter_map(|hash| {
                self.payloads.get(hash).map(|(idx, p)| (*idx, p.clone()))
            })
            .collect();

        // Now generate proofs (needs &mut self for rebuild)
        let mut results = Vec::new();
        for (leaf_index, payload) in matches {
            if let Ok(proof) = self.proof(leaf_index) {
                results.push(SearchResult { payload, leaf_index, proof });
            }
        }

        results
    }

    /// Direct hash lookup. O(1).
    pub fn lookup(&mut self, hash: &[u8; 32]) -> Option<SearchResult> {
        let (leaf_index, payload) = self.payloads.get(hash)?.clone();
        let proof = self.proof(leaf_index).ok()?;
        Some(SearchResult {
            payload,
            leaf_index,
            proof,
        })
    }

    /// Lookup by hex hash.
    pub fn lookup_hex(&mut self, hex: &str) -> Result<Option<SearchResult>, String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 { return Err("Expected 64-char hex".into()); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(self.lookup(&arr))
    }

    // ── Manifest verification (Finding #15: detect JSON poisoning) ──

    /// Compute and store the SHA3-256 manifest of raw JSON data.
    /// Called during INDEX_LOAD before parsing. If the manifest doesn't match
    /// a previously signed manifest, the load is rejected.
    pub fn compute_manifest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Sign a manifest with the internal seal key.
    pub fn sign_manifest(&self, manifest: &[u8; 32]) -> Result<[u8; 32], String> {
        let key = self.seal_key.as_ref().ok_or("No seal key set")?;
        let sign_key = derive_key(key, MANIFEST_HKDF_INFO);
        let mut mac = HmacSha3::new_from_slice(&sign_key)
            .map_err(|_| "HMAC init failed")?;
        mac.update(manifest);
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verify a manifest signature.
    pub fn verify_manifest(&self, manifest: &[u8; 32], signature: &[u8; 32]) -> Result<bool, String> {
        let expected = self.sign_manifest(manifest)?;
        Ok(ct_eq(&expected, signature))
    }

    pub fn set_manifest(&mut self, manifest: [u8; 32]) {
        self.loaded_manifest = Some(manifest);
    }

    // ── Merkle tree operations ──

    pub fn root(&mut self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() { return None; }
        self.rebuild();
        self.layers.last().and_then(|l| l.first().copied())
    }

    pub fn root_hex(&mut self) -> Option<String> {
        self.root().map(|r| hex_encode(&r))
    }

    /// Seal the root using the internally-derived key (Finding #2).
    pub fn seal_root(&mut self) -> Result<String, String> {
        let key = self.seal_key.ok_or("No seal key set. Call set_seal_key_material first.")?;
        let root = self.root().ok_or("Empty tree")?;
        let mut mac = HmacSha3::new_from_slice(&key)
            .map_err(|_| "HMAC init failed")?;
        mac.update(&root);
        let seal: [u8; 32] = mac.finalize().into_bytes().into();
        self.root_seal = Some(seal);
        Ok(hex_encode(&seal))
    }

    /// Verify a root seal using the internally-derived key.
    pub fn verify_seal(&mut self, seal_hex: &str) -> Result<bool, String> {
        let key = self.seal_key.ok_or("No seal key set")?;
        let root = self.root().ok_or("Empty tree")?;
        let expected = hex_decode(seal_hex)?;
        if expected.len() != 32 { return Err("Seal must be 64 hex chars".into()); }

        let mut mac = HmacSha3::new_from_slice(&key)
            .map_err(|_| "HMAC init failed")?;
        mac.update(&root);
        let computed: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(ct_eq(&computed, &expected))
    }

    pub fn proof(&mut self, index: usize) -> Result<MerkleProof, String> {
        if index >= self.leaves.len() {
            return Err(format!("Index {} out of range (0-{})", index, self.leaves.len() - 1));
        }
        self.rebuild();

        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = index;

        for level in 0..self.layers.len() - 1 {
            let layer = &self.layers[level];
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let dir = if idx % 2 == 0 { "right" } else { "left" };

            if sibling_idx < layer.len() {
                siblings.push(layer[sibling_idx]);
            } else {
                siblings.push(layer[idx]);
            }
            directions.push(dir.to_string());
            idx /= 2;
        }

        let root = self.root().ok_or("Empty tree")?;

        Ok(MerkleProof {
            leaf_hash: self.leaves[index],
            leaf_index: index,
            siblings,
            directions,
            root,
        })
    }

    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf_hash;
        for (sibling, direction) in proof.siblings.iter().zip(proof.directions.iter()) {
            if direction == "right" {
                current = hash_node(&current, sibling);
            } else {
                current = hash_node(sibling, &current);
            }
        }
        ct_eq(&current, &proof.root)
    }

    // ── Stats ──

    pub fn stats(&self) -> IndexStats {
        let mut keywords_total = 0;
        for hashes in self.keyword_index.values() {
            keywords_total += hashes.len();
        }
        IndexStats {
            version: TREE_VERSION,
            artifact_count: self.payloads.len(),
            leaf_count: self.leaves.len(),
            keyword_entries: self.keyword_index.len(),
            keyword_refs: keywords_total,
            has_seal: self.root_seal.is_some(),
            has_manifest: self.loaded_manifest.is_some(),
        }
    }

    // ── Reset ──

    pub fn reset(&mut self) {
        self.leaves.clear();
        self.layers.clear();
        self.dirty = true;
        self.root_seal = None;
        self.payloads.clear();
        self.keyword_index.clear();
        self.tier_index.clear();
        self.loaded_manifest = None;
        // seal_key preserved across resets
    }

    // ── Internal ──

    fn rebuild(&mut self) {
        if !self.dirty || self.leaves.is_empty() { return; }

        let n = self.leaves.len();
        let target = n.next_power_of_two().max(2);
        let mut padded = self.leaves.clone();
        padded.resize(target, [0u8; 32]);

        self.layers = vec![padded.clone()];
        let mut current = padded;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                let left = &pair[0];
                let right = if pair.len() > 1 { &pair[1] } else { left };
                next.push(hash_node(left, right));
            }
            self.layers.push(next.clone());
            current = next;
        }

        self.dirty = false;
    }
}

pub struct IndexStats {
    pub version: u8,
    pub artifact_count: usize,
    pub leaf_count: usize,
    pub keyword_entries: usize,
    pub keyword_refs: usize,
    pub has_seal: bool,
    pub has_manifest: bool,
}

pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<String>,
    pub root: [u8; 32],
}

impl MerkleProof {
    pub fn to_response(&self) -> String {
        let siblings_hex: Vec<String> = self.siblings.iter().map(|s| hex_encode(s)).collect();
        format!(
            "OK {} {} {} {} {}",
            hex_encode(&self.leaf_hash),
            self.leaf_index,
            siblings_hex.join(","),
            self.directions.join(","),
            hex_encode(&self.root),
        )
    }
}

// ── Hex utilities ──

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 { return Err("Odd hex length".into()); }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex".into()))
        .collect()
}

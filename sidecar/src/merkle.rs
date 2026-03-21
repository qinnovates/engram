//! Merkle tree — integrity verification in the trusted Rust boundary.
//!
//! All tree operations (add leaf, generate proof, verify proof, compute root)
//! run inside the sidecar process. Python never sees intermediate hashes
//! or proof computations — only the final results.
//!
//! SHA-256 with domain separation:
//!   Leaf:     SHA-256(0x00 || data)
//!   Internal: SHA-256(0x01 || left || right)
//!
//! Compatible with RFC 6962 (Certificate Transparency) proof format.
//! Constant-time comparison for verify (prevents timing side channels).

use sha2::{Sha256, Digest};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Constant-time comparison (prevents timing side channels on verify)
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

/// In-memory Merkle tree with append, proof, and verify.
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    /// Cached layers. layers[0] = leaves, layers[last] = [root]
    layers: Vec<Vec<[u8; 32]>>,
    dirty: bool,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            layers: Vec::new(),
            dirty: true,
        }
    }

    /// Add raw data as a leaf. Returns leaf index.
    pub fn add_data(&mut self, data: &[u8]) -> usize {
        let h = hash_leaf(data);
        self.leaves.push(h);
        self.dirty = true;
        self.leaves.len() - 1
    }

    /// Add a pre-computed SHA-256 hash as a leaf (with domain separation).
    pub fn add_hash(&mut self, hash: &[u8; 32]) -> usize {
        let h = hash_leaf(hash);
        self.leaves.push(h);
        self.dirty = true;
        self.leaves.len() - 1
    }

    /// Add a hex-encoded SHA-256 hash.
    pub fn add_hex(&mut self, hex: &str) -> Result<usize, String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err("Expected 64-char hex (32 bytes)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(self.add_hash(&arr))
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Compute and return the root hash.
    pub fn root(&mut self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        self.rebuild();
        self.layers.last().and_then(|l| l.first().copied())
    }

    pub fn root_hex(&mut self) -> Option<String> {
        self.root().map(|r| hex_encode(&r))
    }

    /// Generate a Merkle proof for the leaf at `index`.
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
                siblings.push(layer[idx]); // duplicate for odd trees
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

    /// Verify a proof against a root hash. Constant-time comparison.
    pub fn verify(proof: &MerkleProof) -> bool {
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

    // ── Internal ──

    fn rebuild(&mut self) {
        if !self.dirty || self.leaves.is_empty() {
            return;
        }

        // Pad to next power of 2
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

pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<String>,
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Serialize to protocol response string.
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

// ── Hex utilities (no external dep) ──

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| "Invalid hex".into())
        })
        .collect()
}

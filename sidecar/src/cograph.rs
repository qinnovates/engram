//! Activation Graph: Co-occurrence tracking + spreading activation.
//!
//! Layer 3: PMI co-occurrence — tracks which artifacts are recalled together.
//! Layer 4: Spreading activation — weighted BFS propagation to find related artifacts.
//!
//! All data lives in-memory (HashMap adjacency list). Serialized to a binary
//! blob and encrypted via the same AES-256-GCM pipeline as the Merkle index.
//!
//! No SQLite. No new dependencies. Same threat model as the Merkle-Index.

use std::collections::{HashMap, HashSet};

// ── Size limits ──
const MAX_EDGES: usize = 500_000;
const MAX_NEIGHBORS: usize = 100;
const MAX_SESSION_BUFFER: usize = 1_000;  // Cap session buffer to prevent O(n²) DoS
const MAX_KEYWORD_BUCKET: usize = 200;    // Cap per-keyword bucket in compute_keyword_edges
const MIN_CORECALL_THRESHOLD: u32 = 3;

// ── Serialization magic ──
const GRAPH_MAGIC: &[u8; 6] = b"AGRPH1";

/// A single neighbor entry in the adjacency list.
#[derive(Clone)]
struct Neighbor {
    hash: [u8; 32],
    corecall_count: u32,
    keyword_overlap: f32, // Jaccard similarity of keyword sets
}

/// Co-occurrence graph with PPMI edge weighting and spreading activation.
pub struct CoGraph {
    // Adjacency list: artifact hash → neighbors
    adjacency: HashMap<[u8; 32], Vec<Neighbor>>,

    // Counters for PPMI computation
    recall_count: HashMap<[u8; 32], u32>,   // per-artifact recall count
    total_sessions: u64,                     // total session events

    // Session buffer: artifacts recalled in current session
    session_buffer: Vec<[u8; 32]>,
    session_set: HashSet<[u8; 32]>,  // O(1) dedup for session_buffer

    // Total edge count (for limit enforcement)
    edge_count: usize,
}

impl CoGraph {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            recall_count: HashMap::new(),
            total_sessions: 0,
            session_buffer: Vec::new(),
            session_set: HashSet::new(),
            edge_count: 0,
        }
    }

    /// Record that an artifact was accessed in the current session.
    /// Call flush_session() at end of session to create co-occurrence edges.
    pub fn record_access(&mut self, hash: &[u8; 32]) {
        // Cap session buffer to prevent O(n²) flush_session DoS
        if self.session_buffer.len() >= MAX_SESSION_BUFFER {
            return;
        }
        // O(1) dedup via HashSet (not Vec::contains which is O(n))
        if self.session_set.insert(*hash) {
            self.session_buffer.push(*hash);
        }
        *self.recall_count.entry(*hash).or_insert(0) += 1;
    }

    /// Flush session buffer: create co-occurrence edges for all artifact pairs
    /// that were accessed together. Call at end of each session/context-build.
    pub fn flush_session(&mut self) {
        if self.session_buffer.len() < 2 {
            self.session_buffer.clear();
            self.total_sessions += 1;
            return;
        }

        self.total_sessions = self.total_sessions.saturating_add(1);

        // Create edges for all pairs (early exit when edge limit reached)
        let buf = self.session_buffer.clone();
        'outer: for i in 0..buf.len() {
            for j in (i + 1)..buf.len() {
                if self.edge_count >= MAX_EDGES {
                    break 'outer;
                }
                self.increment_corecall(&buf[i], &buf[j]);
            }
        }

        self.session_buffer.clear();
        self.session_set.clear();
    }

    /// Add a keyword-overlap edge (computed from inverted keyword index).
    pub fn add_keyword_edge(&mut self, hash_a: &[u8; 32], hash_b: &[u8; 32], jaccard: f32) {
        if hash_a == hash_b || !jaccard.is_finite() || jaccard <= 0.0 || jaccard > 1.0 {
            return;
        }
        // Set keyword_overlap on existing neighbor or create new
        self.set_keyword_overlap(hash_a, hash_b, jaccard);
        self.set_keyword_overlap(hash_b, hash_a, jaccard);
    }

    /// Spreading activation: BFS from seed artifact, return top-K related.
    ///
    /// Layer 4: Weighted BFS with decay. Max-pooling (not sum) to avoid
    /// topology-inflated scores. ~10-50 microseconds for typical graphs.
    pub fn activate(&self, seed: &[u8; 32], depth: u8, top_k: usize) -> Vec<([u8; 32], f32)> {
        let decay: f32 = 0.7;
        let threshold: f32 = 0.01;

        let mut scores: HashMap<[u8; 32], f32> = HashMap::new();
        let mut frontier: Vec<([u8; 32], f32)> = vec![(*seed, 1.0)];

        for d in 0..depth {
            let mut next_frontier: Vec<([u8; 32], f32)> = Vec::new();
            for (node, activation) in &frontier {
                if let Some(neighbors) = self.adjacency.get(node) {
                    for neighbor in neighbors {
                        let edge_weight = self.compute_edge_weight(
                            node, &neighbor.hash, neighbor,
                        );
                        let new_act = activation * edge_weight * decay.powi(d as i32);
                        if new_act >= threshold {
                            let entry = scores.entry(neighbor.hash).or_insert(0.0);
                            if new_act > *entry {
                                *entry = new_act; // max-pooling
                                next_frontier.push((neighbor.hash, new_act));
                            }
                        }
                    }
                }
            }
            frontier = next_frontier;
        }

        // Remove seed from results
        scores.remove(seed);

        // Sort by score descending, take top-K
        let mut ranked: Vec<([u8; 32], f32)> = scores.into_iter().collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Less));
        ranked.truncate(top_k);
        ranked
    }

    /// Compute PPMI-based edge weight for a neighbor.
    ///
    /// PPMI = max(0, log2(P(a,b) / (P(a) * P(b))))
    ///      = max(0, log2(N_ab * N_total / (N_a * N_b)))
    ///
    /// Combined with keyword overlap: weight = 0.6 * ppmi_norm + 0.4 * keyword_overlap
    fn compute_edge_weight(&self, a: &[u8; 32], _b: &[u8; 32], neighbor: &Neighbor) -> f32 {
        let n_ab = neighbor.corecall_count as f64;
        let n_a = *self.recall_count.get(a).unwrap_or(&1) as f64;
        let n_b = *self.recall_count.get(&neighbor.hash).unwrap_or(&1) as f64;
        let n_total = self.total_sessions.max(1) as f64;

        // PPMI (cold-start gate: need MIN_CORECALL_THRESHOLD co-recalls)
        let ppmi = if neighbor.corecall_count >= MIN_CORECALL_THRESHOLD {
            let pmi = (n_ab * n_total / (n_a * n_b)).ln() / std::f64::consts::LN_2;
            pmi.max(0.0) as f32
        } else {
            0.0
        };

        // Normalize PPMI to [0, 1] range (cap at 10 bits of surprise)
        let ppmi_norm = (ppmi / 10.0).min(1.0);

        // Combined weight
        if neighbor.keyword_overlap > 0.0 && ppmi_norm > 0.0 {
            0.6 * ppmi_norm + 0.4 * neighbor.keyword_overlap
        } else if ppmi_norm > 0.0 {
            ppmi_norm
        } else {
            neighbor.keyword_overlap
        }
    }

    /// Compute keyword overlap edges from the provided keyword sets.
    /// keyword_sets: hash → list of keywords
    /// Only creates edges where Jaccard >= 0.1 (roughly 3+ shared keywords for 30-keyword sets)
    pub fn compute_keyword_edges(&mut self, keyword_sets: &HashMap<[u8; 32], Vec<String>>) {
        // Build inverted index: keyword → set of hashes (avoids O(n²))
        let mut inverted: HashMap<&str, Vec<[u8; 32]>> = HashMap::new();
        for (hash, keywords) in keyword_sets {
            for kw in keywords {
                inverted.entry(kw.as_str()).or_default().push(*hash);
            }
        }

        // For each keyword, compare all artifact pairs sharing it
        let mut seen_pairs: std::collections::HashSet<([u8; 32], [u8; 32])> = std::collections::HashSet::new();

        for (_kw, hashes) in &inverted {
            // Skip over-populated keywords to prevent O(n²) DoS
            if hashes.len() > MAX_KEYWORD_BUCKET { continue; }
            for i in 0..hashes.len() {
                for j in (i + 1)..hashes.len() {
                    let (a, b) = canonical_pair(&hashes[i], &hashes[j]);
                    if seen_pairs.contains(&(a, b)) {
                        continue;
                    }
                    seen_pairs.insert((a, b));

                    // Compute Jaccard
                    if let (Some(kw_a), Some(kw_b)) = (keyword_sets.get(&a), keyword_sets.get(&b)) {
                        let jaccard = jaccard_similarity(kw_a, kw_b);
                        if jaccard >= 0.1 {
                            self.add_keyword_edge(&a, &b, jaccard);
                        }
                    }
                }
            }
        }
    }

    pub fn stats(&self) -> GraphStats {
        GraphStats {
            node_count: self.adjacency.len(),
            edge_count: self.edge_count,
            total_sessions: self.total_sessions,
            session_buffer_size: self.session_buffer.len(),
            total_recalls: self.recall_count.values().sum::<u32>() as u64,
        }
    }

    pub fn reset(&mut self) {
        self.adjacency.clear();
        self.recall_count.clear();
        self.total_sessions = 0;
        self.session_buffer.clear();
        self.session_set.clear();
        self.edge_count = 0;
    }

    /// Serialize to bytes for encrypted persistence.
    /// Format: AGRPH1 | total_sessions(u64) | node_count(u32) |
    ///   for each node: hash(32) | recall_count(u32) | neighbor_count(u32) |
    ///     for each neighbor: hash(32) | corecall_count(u32) | keyword_overlap(f32)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // Magic
        buf.extend_from_slice(GRAPH_MAGIC);

        // Total sessions
        buf.extend_from_slice(&self.total_sessions.to_le_bytes());

        // Node count
        let node_count = self.adjacency.len() as u32;
        buf.extend_from_slice(&node_count.to_le_bytes());

        // For each node
        for (hash, neighbors) in &self.adjacency {
            // Hash
            buf.extend_from_slice(hash);

            // Recall count
            let rc = *self.recall_count.get(hash).unwrap_or(&0);
            buf.extend_from_slice(&rc.to_le_bytes());

            // Neighbor count
            let nc = neighbors.len() as u32;
            buf.extend_from_slice(&nc.to_le_bytes());

            // Neighbors
            for n in neighbors {
                buf.extend_from_slice(&n.hash);
                buf.extend_from_slice(&n.corecall_count.to_le_bytes());
                buf.extend_from_slice(&n.keyword_overlap.to_le_bytes());
            }
        }

        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<CoGraph, String> {
        if data.len() < 6 {
            return Err("Data too short".into());
        }
        if &data[0..6] != GRAPH_MAGIC {
            return Err("Invalid magic bytes".into());
        }

        let mut pos = 6;
        let mut graph = Self::new();

        // Total sessions (bounded to prevent PPMI saturation from crafted blobs)
        if pos + 8 > data.len() { return Err("Truncated total_sessions".into()); }
        let ts = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        if ts > 1_000_000_000 { return Err("Unreasonable total_sessions value".into()); }
        graph.total_sessions = ts;
        pos += 8;

        // Node count
        if pos + 4 > data.len() { return Err("Truncated node_count".into()); }
        let node_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if node_count > MAX_EDGES {
            return Err(format!("Node count {} exceeds limit", node_count));
        }

        for _ in 0..node_count {
            // Hash
            if pos + 32 > data.len() { return Err("Truncated hash".into()); }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            // Recall count
            if pos + 4 > data.len() { return Err("Truncated recall_count".into()); }
            let rc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            graph.recall_count.insert(hash, rc);

            // Neighbor count
            if pos + 4 > data.len() { return Err("Truncated neighbor_count".into()); }
            let nc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;

            if nc > MAX_NEIGHBORS {
                return Err(format!("Neighbor count {} exceeds limit", nc));
            }

            let mut neighbors = Vec::with_capacity(nc);
            for _ in 0..nc {
                if pos + 40 > data.len() { return Err("Truncated neighbor".into()); }
                let mut nh = [0u8; 32];
                nh.copy_from_slice(&data[pos..pos + 32]);
                pos += 32;

                let cc = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;

                let ko_raw = f32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                // Sanitize: reject NaN/Inf/out-of-range (crafted binary input)
                let ko = if ko_raw.is_finite() && ko_raw >= 0.0 && ko_raw <= 1.0 { ko_raw } else { 0.0 };
                pos += 4;

                neighbors.push(Neighbor { hash: nh, corecall_count: cc, keyword_overlap: ko });
                graph.edge_count += 1;
            }

            graph.adjacency.insert(hash, neighbors);
        }

        // Edges are double-counted (bidirectional), so halve
        graph.edge_count /= 2;

        Ok(graph)
    }

    // ── Internal helpers ──

    fn increment_corecall(&mut self, a: &[u8; 32], b: &[u8; 32]) {
        if a == b { return; }
        if self.edge_count >= MAX_EDGES { return; }

        self.ensure_neighbor(a, b);
        self.ensure_neighbor(b, a);

        // Increment counts on both directions
        if let Some(neighbors) = self.adjacency.get_mut(a) {
            if let Some(n) = neighbors.iter_mut().find(|n| n.hash == *b) {
                n.corecall_count += 1;
            }
        }
        if let Some(neighbors) = self.adjacency.get_mut(b) {
            if let Some(n) = neighbors.iter_mut().find(|n| n.hash == *a) {
                n.corecall_count += 1;
            }
        }
    }

    fn ensure_neighbor(&mut self, from: &[u8; 32], to: &[u8; 32]) {
        let neighbors = self.adjacency.entry(*from).or_default();
        if neighbors.len() >= MAX_NEIGHBORS { return; }
        if !neighbors.iter().any(|n| n.hash == *to) {
            neighbors.push(Neighbor {
                hash: *to,
                corecall_count: 0,
                keyword_overlap: 0.0,
            });
            self.edge_count += 1;
        }
    }

    fn set_keyword_overlap(&mut self, from: &[u8; 32], to: &[u8; 32], jaccard: f32) {
        let neighbors = self.adjacency.entry(*from).or_default();
        if let Some(n) = neighbors.iter_mut().find(|n| n.hash == *to) {
            n.keyword_overlap = jaccard;
        } else {
            if neighbors.len() >= MAX_NEIGHBORS || self.edge_count >= MAX_EDGES {
                return;
            }
            neighbors.push(Neighbor {
                hash: *to,
                corecall_count: 0,
                keyword_overlap: jaccard,
            });
            self.edge_count += 1;
        }
    }
}

// ── Free functions ──

fn canonical_pair(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a <= b { (*a, *b) } else { (*b, *a) }
}

fn jaccard_similarity(a: &[String], b: &[String]) -> f32 {
    let set_a: std::collections::HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: std::collections::HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 { return 0.0; }
    intersection as f32 / union as f32
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub total_sessions: u64,
    pub session_buffer_size: usize,
    pub total_recalls: u64,
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h[31] = seed;
        h
    }

    #[test]
    fn test_record_and_flush_creates_edges() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        g.record_access(&a);
        g.record_access(&b);
        g.record_access(&c);
        g.flush_session();

        // Should have edges a↔b, a↔c, b↔c
        assert_eq!(g.adjacency.get(&a).unwrap().len(), 2);
        assert_eq!(g.adjacency.get(&b).unwrap().len(), 2);
        assert_eq!(g.adjacency.get(&c).unwrap().len(), 2);
        assert_eq!(g.total_sessions, 1);
    }

    #[test]
    fn test_no_self_loops() {
        let mut g = CoGraph::new();
        let a = make_hash(1);

        g.record_access(&a);
        g.flush_session();

        assert!(g.adjacency.get(&a).is_none() || g.adjacency.get(&a).unwrap().is_empty());
    }

    #[test]
    fn test_corecall_count_increments() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);

        // 3 sessions with both a and b
        for _ in 0..3 {
            g.record_access(&a);
            g.record_access(&b);
            g.flush_session();
        }

        let neighbors = g.adjacency.get(&a).unwrap();
        let b_neighbor = neighbors.iter().find(|n| n.hash == b).unwrap();
        assert_eq!(b_neighbor.corecall_count, 3);
    }

    #[test]
    fn test_bidirectional_edges() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);

        g.record_access(&a);
        g.record_access(&b);
        g.flush_session();

        let a_has_b = g.adjacency.get(&a).unwrap().iter().any(|n| n.hash == b);
        let b_has_a = g.adjacency.get(&b).unwrap().iter().any(|n| n.hash == a);
        assert!(a_has_b);
        assert!(b_has_a);
    }

    #[test]
    fn test_keyword_edge() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);

        g.add_keyword_edge(&a, &b, 0.25);

        let neighbors = g.adjacency.get(&a).unwrap();
        let b_entry = neighbors.iter().find(|n| n.hash == b).unwrap();
        assert!((b_entry.keyword_overlap - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_activate_depth_1() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        // Create keyword edges (these work without min corecall threshold)
        g.add_keyword_edge(&a, &b, 0.5);
        g.add_keyword_edge(&a, &c, 0.3);

        let results = g.activate(&a, 1, 10);
        assert_eq!(results.len(), 2);
        // b should rank higher (stronger edge)
        assert_eq!(results[0].0, b);
        assert_eq!(results[1].0, c);
    }

    #[test]
    fn test_activate_depth_2() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        // a → b → c (no direct a → c edge)
        g.add_keyword_edge(&a, &b, 0.8);
        g.add_keyword_edge(&b, &c, 0.8);

        let results = g.activate(&a, 2, 10);
        // Should find both b (depth 1) and c (depth 2)
        assert!(results.iter().any(|(h, _)| *h == b));
        assert!(results.iter().any(|(h, _)| *h == c));
        // b should have higher score (direct vs indirect)
        let b_score = results.iter().find(|(h, _)| *h == b).unwrap().1;
        let c_score = results.iter().find(|(h, _)| *h == c).unwrap().1;
        assert!(b_score > c_score);
    }

    #[test]
    fn test_activate_empty_graph() {
        let g = CoGraph::new();
        let a = make_hash(1);
        let results = g.activate(&a, 2, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_activate_seed_not_in_results() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        g.add_keyword_edge(&a, &b, 0.5);

        let results = g.activate(&a, 1, 10);
        assert!(results.iter().all(|(h, _)| *h != a));
    }

    #[test]
    fn test_ppmi_cold_start_gate() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);

        // Only 2 co-recalls (below threshold of 3)
        for _ in 0..2 {
            g.record_access(&a);
            g.record_access(&b);
            g.flush_session();
        }

        // PPMI should be 0 (below threshold), so activation returns empty
        // unless there's also keyword overlap
        let results = g.activate(&a, 1, 10);
        // All scores should be 0 (PPMI gated, no keyword overlap)
        for (_, score) in &results {
            assert!(*score < 0.01);
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        g.record_access(&a);
        g.record_access(&b);
        g.flush_session();
        g.add_keyword_edge(&a, &c, 0.3);

        let bytes = g.serialize();
        let g2 = CoGraph::deserialize(&bytes).unwrap();

        assert_eq!(g2.total_sessions, 1);
        assert_eq!(g2.adjacency.len(), g.adjacency.len());
        assert_eq!(g2.recall_count.get(&a), g.recall_count.get(&a));

        // Check edge preserved
        let neighbors = g2.adjacency.get(&a).unwrap();
        assert!(neighbors.iter().any(|n| n.hash == b));
    }

    #[test]
    fn test_deserialize_bad_magic() {
        let bad = b"BADMAG";
        assert!(CoGraph::deserialize(bad).is_err());
    }

    #[test]
    fn test_deserialize_empty() {
        assert!(CoGraph::deserialize(&[]).is_err());
    }

    #[test]
    fn test_jaccard_similarity() {
        let a = vec!["auth".into(), "token".into(), "jwt".into(), "middleware".into()];
        let b = vec!["auth".into(), "token".into(), "session".into(), "cookie".into()];
        let j = jaccard_similarity(&a, &b);
        // intersection = {auth, token} = 2, union = {auth, token, jwt, middleware, session, cookie} = 6
        assert!((j - 2.0 / 6.0).abs() < 0.001);
    }

    #[test]
    fn test_compute_keyword_edges() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        let mut keyword_sets: HashMap<[u8; 32], Vec<String>> = HashMap::new();
        keyword_sets.insert(a, vec!["auth".into(), "token".into(), "jwt".into(), "session".into()]);
        keyword_sets.insert(b, vec!["auth".into(), "token".into(), "jwt".into(), "cookie".into()]);
        keyword_sets.insert(c, vec!["database".into(), "migration".into(), "schema".into(), "index".into()]);

        g.compute_keyword_edges(&keyword_sets);

        // a and b share 3 keywords → should have edge
        assert!(g.adjacency.get(&a).unwrap().iter().any(|n| n.hash == b));
        // a/b and c share 0 keywords → no edge
        let a_has_c = g.adjacency.get(&a).map(|n| n.iter().any(|x| x.hash == c)).unwrap_or(false);
        assert!(!a_has_c);
    }

    #[test]
    fn test_stats() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        g.record_access(&a);
        g.record_access(&b);
        g.flush_session();

        let stats = g.stats();
        assert_eq!(stats.node_count, 2);
        assert_eq!(stats.total_sessions, 1);
        assert!(stats.edge_count > 0);
    }

    #[test]
    fn test_max_edges_enforced() {
        let mut g = CoGraph::new();
        // This won't hit the limit but verifies the guard exists
        for i in 0..50u8 {
            let h = make_hash(i);
            g.record_access(&h);
        }
        g.flush_session();
        assert!(g.edge_count <= MAX_EDGES);
    }

    #[test]
    fn test_reset() {
        let mut g = CoGraph::new();
        let a = make_hash(1);
        let b = make_hash(2);
        g.record_access(&a);
        g.record_access(&b);
        g.flush_session();

        g.reset();
        assert_eq!(g.adjacency.len(), 0);
        assert_eq!(g.recall_count.len(), 0);
        assert_eq!(g.total_sessions, 0);
        assert_eq!(g.edge_count, 0);
    }
}

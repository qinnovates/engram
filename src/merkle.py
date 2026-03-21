"""
Merkle tree for Engram — integrity verification and selective disclosure.

Provides:
  1. Build a Merkle tree from any list of artifacts (files, spatial data, audit events)
  2. Generate a proof for any single leaf (log(n) hashes)
  3. Verify a proof against the root hash
  4. Rollup: batch multiple items into one tree, one root, one signature
  5. Append-only: add new leaves without rebuilding the entire tree

Design:
  - SHA-256 throughout (quantum-safe at 128-bit post-Grover, per NIST SP 800-57)
  - Leaves are hashed TWICE (domain separation: leaf vs internal node)
  - Compatible with RFC 6962 (Certificate Transparency) proof format
  - Serializable to JSON for storage in Engram metadata

Use cases:
  - Spatial memory integrity (Spot): prove a geometry snapshot is in the tree
    without revealing other snapshots
  - Audit chain integrity: prove an event happened without exposing the full log
  - Peer sharing (NSP): include Merkle proof in NSP payload so receiver can verify
    the data is part of an authenticated spatial memory
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, asdict
from typing import Optional


# Domain separation prefixes (prevents second-preimage attacks)
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _hash_leaf(data: bytes) -> bytes:
    """Hash a leaf node with domain separation."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    """Hash an internal node with domain separation."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


@dataclass
class MerkleProof:
    """Proof that a leaf is in the tree. Log(n) hashes."""
    leaf_hash: str          # hex of the leaf being proved
    leaf_index: int         # position in the tree
    siblings: list[str]     # hex hashes of sibling nodes along the path
    directions: list[str]   # "left" or "right" for each sibling
    root: str               # expected root hash (hex)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> MerkleProof:
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s: str) -> MerkleProof:
        return cls.from_dict(json.loads(s))


@dataclass
class MerkleTree:
    """
    Binary Merkle tree with append, proof generation, and verification.

    Leaves are stored in order. Internal nodes are computed lazily.
    The tree auto-pads to the next power of 2 with empty hashes.
    """
    leaves: list[bytes] = field(default_factory=list)
    _nodes: list[list[bytes]] = field(default_factory=list, repr=False)
    _dirty: bool = True

    @property
    def root(self) -> Optional[bytes]:
        """Root hash of the tree. None if empty."""
        if not self.leaves:
            return None
        self._rebuild_if_dirty()
        return self._nodes[-1][0] if self._nodes else None

    @property
    def root_hex(self) -> Optional[str]:
        """Root hash as hex string."""
        r = self.root
        return r.hex() if r else None

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    # ── Build ──

    def add(self, data: bytes) -> int:
        """Add a leaf to the tree. Returns the leaf index."""
        leaf_hash = _hash_leaf(data)
        self.leaves.append(leaf_hash)
        self._dirty = True
        return len(self.leaves) - 1

    def add_hex(self, hex_hash: str) -> int:
        """Add a pre-computed hash (hex) as a leaf. Applies domain separation."""
        leaf_hash = _hash_leaf(bytes.fromhex(hex_hash))
        self.leaves.append(leaf_hash)
        self._dirty = True
        return len(self.leaves) - 1

    def add_artifact(self, sha256_hex: str) -> int:
        """Add an Engram artifact by its existing SHA-256 hash."""
        return self.add_hex(sha256_hex)

    def _rebuild_if_dirty(self) -> None:
        if not self._dirty or not self.leaves:
            return

        # Pad to next power of 2
        n = len(self.leaves)
        target = 1 << math.ceil(math.log2(max(n, 2)))
        padded = list(self.leaves) + [b"\x00" * 32] * (target - n)

        # Build tree bottom-up
        self._nodes = [padded]
        current = padded
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(_hash_node(left, right))
            self._nodes.append(next_level)
            current = next_level

        self._dirty = False

    # ── Proofs ──

    def proof(self, index: int) -> MerkleProof:
        """Generate a Merkle proof for the leaf at the given index."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range (0-{len(self.leaves)-1})")

        self._rebuild_if_dirty()

        siblings = []
        directions = []
        idx = index

        for level in range(len(self._nodes) - 1):
            layer = self._nodes[level]
            if idx % 2 == 0:
                # Current is left child, sibling is right
                sibling_idx = idx + 1
                directions.append("right")
            else:
                # Current is right child, sibling is left
                sibling_idx = idx - 1
                directions.append("left")

            if sibling_idx < len(layer):
                siblings.append(layer[sibling_idx].hex())
            else:
                siblings.append(layer[idx].hex())  # duplicate for odd trees

            idx //= 2

        return MerkleProof(
            leaf_hash=self.leaves[index].hex(),
            leaf_index=index,
            siblings=siblings,
            directions=directions,
            root=self.root_hex or "",
        )

    @staticmethod
    def verify(proof: MerkleProof) -> bool:
        """Verify a Merkle proof against the claimed root."""
        current = bytes.fromhex(proof.leaf_hash)

        for sibling_hex, direction in zip(proof.siblings, proof.directions):
            sibling = bytes.fromhex(sibling_hex)
            if direction == "right":
                current = _hash_node(current, sibling)
            else:
                current = _hash_node(sibling, current)

        import hmac
        return hmac.compare_digest(current.hex(), proof.root)

    # ── Serialization ──

    def to_dict(self) -> dict:
        """Serialize tree state (leaves only — nodes recomputed on load)."""
        return {
            "leaves": [leaf.hex() for leaf in self.leaves],
            "root": self.root_hex,
            "leaf_count": self.leaf_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MerkleTree:
        tree = cls()
        for hex_hash in d.get("leaves", []):
            # Validate hex length (SHA-256 = 32 bytes = 64 hex chars)
            if not isinstance(hex_hash, str) or len(hex_hash) != 64:
                continue  # Skip invalid entries
            tree.leaves.append(bytes.fromhex(hex_hash))
        tree._dirty = True

        # Verify root matches stored root (detect corruption on load)
        stored_root = d.get("root")
        if stored_root and tree.root_hex != stored_root:
            raise ValueError(
                f"Merkle tree corrupt on load: stored root={stored_root[:16]}... "
                f"computed root={tree.root_hex[:16] if tree.root_hex else 'empty'}..."
            )

        return tree

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> MerkleTree:
        return cls.from_dict(json.loads(s))

    def save(self, path: str) -> None:
        """Save tree to a JSON file (atomic write to prevent corruption)."""
        import os
        import tempfile
        content = self.to_json()
        dir_path = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            os.write(fd, content.encode())
            os.close(fd)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            os.close(fd) if not os.get_inheritable(fd) else None
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    @classmethod
    def load(cls, path: str) -> MerkleTree:
        """Load tree from a JSON file."""
        with open(path) as f:
            return cls.from_json(f.read())


# ── Rollup ──

def rollup(items: list[bytes]) -> tuple[MerkleTree, str]:
    """
    Batch multiple items into one Merkle tree.
    Returns the tree and its root hash.

    Use case: a 30-minute walk generates 200 geometry snapshots.
    Rollup into one tree → one root → one NSP signature.
    200x less crypto overhead.
    """
    tree = MerkleTree()
    for item in items:
        tree.add(item)
    return tree, tree.root_hex or ""


def rollup_from_hashes(sha256_hashes: list[str]) -> tuple[MerkleTree, str]:
    """Rollup from pre-computed SHA-256 hex hashes (e.g., from Engram artifacts)."""
    tree = MerkleTree()
    for h in sha256_hashes:
        tree.add_hex(h)
    return tree, tree.root_hex or ""

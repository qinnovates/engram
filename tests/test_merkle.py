"""Tests for Merkle tree — integrity, proofs, rollups."""

import json
import tempfile
from pathlib import Path

from src.merkle import MerkleTree, MerkleProof, rollup, rollup_from_hashes


class TestMerkleTree:

    def test_empty_tree_has_no_root(self):
        tree = MerkleTree()
        assert tree.root is None
        assert tree.root_hex is None

    def test_single_leaf(self):
        tree = MerkleTree()
        tree.add(b"hello")
        assert tree.root is not None
        assert tree.leaf_count == 1

    def test_two_leaves_different_root_than_one(self):
        tree1 = MerkleTree()
        tree1.add(b"hello")

        tree2 = MerkleTree()
        tree2.add(b"hello")
        tree2.add(b"world")

        assert tree1.root_hex != tree2.root_hex

    def test_deterministic_root(self):
        tree1 = MerkleTree()
        tree1.add(b"a")
        tree1.add(b"b")
        tree1.add(b"c")

        tree2 = MerkleTree()
        tree2.add(b"a")
        tree2.add(b"b")
        tree2.add(b"c")

        assert tree1.root_hex == tree2.root_hex

    def test_different_order_different_root(self):
        tree1 = MerkleTree()
        tree1.add(b"a")
        tree1.add(b"b")

        tree2 = MerkleTree()
        tree2.add(b"b")
        tree2.add(b"a")

        assert tree1.root_hex != tree2.root_hex

    def test_tamper_detection(self):
        tree = MerkleTree()
        tree.add(b"original")
        original_root = tree.root_hex

        tree2 = MerkleTree()
        tree2.add(b"tampered")
        assert tree2.root_hex != original_root


class TestMerkleProof:

    def test_proof_for_first_leaf(self):
        tree = MerkleTree()
        tree.add(b"a")
        tree.add(b"b")
        tree.add(b"c")
        tree.add(b"d")

        proof = tree.proof(0)
        assert MerkleTree.verify(proof)

    def test_proof_for_last_leaf(self):
        tree = MerkleTree()
        for i in range(8):
            tree.add(f"item-{i}".encode())

        proof = tree.proof(7)
        assert MerkleTree.verify(proof)

    def test_proof_for_middle_leaf(self):
        tree = MerkleTree()
        for i in range(16):
            tree.add(f"data-{i}".encode())

        proof = tree.proof(7)
        assert MerkleTree.verify(proof)

    def test_proof_fails_with_wrong_root(self):
        tree = MerkleTree()
        tree.add(b"a")
        tree.add(b"b")

        proof = tree.proof(0)
        proof.root = "0" * 64  # fake root
        assert not MerkleTree.verify(proof)

    def test_proof_fails_with_tampered_leaf(self):
        tree = MerkleTree()
        tree.add(b"a")
        tree.add(b"b")

        proof = tree.proof(0)
        proof.leaf_hash = "0" * 64  # fake leaf
        assert not MerkleTree.verify(proof)

    def test_proof_serialization(self):
        tree = MerkleTree()
        tree.add(b"test")
        tree.add(b"data")

        proof = tree.proof(0)
        json_str = proof.to_json()
        restored = MerkleProof.from_json(json_str)

        assert restored.leaf_hash == proof.leaf_hash
        assert restored.root == proof.root
        assert MerkleTree.verify(restored)

    def test_odd_number_of_leaves(self):
        tree = MerkleTree()
        tree.add(b"a")
        tree.add(b"b")
        tree.add(b"c")  # 3 leaves, not a power of 2

        for i in range(3):
            proof = tree.proof(i)
            assert MerkleTree.verify(proof)

    def test_single_leaf_proof(self):
        tree = MerkleTree()
        tree.add(b"only")

        proof = tree.proof(0)
        assert MerkleTree.verify(proof)


class TestRollup:

    def test_rollup_produces_tree_and_root(self):
        items = [b"snapshot-1", b"snapshot-2", b"snapshot-3"]
        tree, root = rollup(items)

        assert root is not None
        assert tree.leaf_count == 3
        assert tree.root_hex == root

    def test_rollup_from_hashes(self):
        import hashlib
        hashes = [hashlib.sha256(f"item-{i}".encode()).hexdigest() for i in range(10)]
        tree, root = rollup_from_hashes(hashes)

        assert tree.leaf_count == 10
        assert root is not None

    def test_rollup_proof_works(self):
        items = [f"geometry-snapshot-{i}".encode() for i in range(200)]
        tree, root = rollup(items)

        # Can prove any single snapshot
        proof = tree.proof(99)
        assert MerkleTree.verify(proof)

        # Root matches
        assert proof.root == root


class TestSerialization:

    def test_save_and_load(self):
        tree = MerkleTree()
        for i in range(10):
            tree.add(f"data-{i}".encode())

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tree.save(f.name)
            loaded = MerkleTree.load(f.name)

        assert loaded.root_hex == tree.root_hex
        assert loaded.leaf_count == tree.leaf_count

    def test_json_roundtrip(self):
        tree = MerkleTree()
        tree.add(b"test")
        tree.add(b"roundtrip")

        json_str = tree.to_json()
        restored = MerkleTree.from_json(json_str)

        assert restored.root_hex == tree.root_hex

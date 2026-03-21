"""Tests for spatial memory extension."""

import tempfile
from pathlib import Path

from src.spatial import (
    SpatialMemory,
    SpatialArtifactType,
    RouteSegment,
    HazardMarker,
    PointOfInterest,
)


class TestSpatialMemory:

    def _make_memory(self) -> SpatialMemory:
        tmp = Path(tempfile.mkdtemp())
        return SpatialMemory(tmp)

    def test_register_hazard(self):
        mem = self._make_memory()
        hazard = HazardMarker(
            hazard_type="stairs_down",
            position=[1.0, 0.0, -5.0],
            step_count=6,
            height_meters=1.2,
            direction="ahead",
        )
        artifact = mem.register_hazard(hazard, confidence=0.9)

        assert artifact.artifact_type == "hazard-marker"
        assert artifact.confidence == 0.9
        assert "stairs_down" in artifact.keywords
        assert mem.tree.leaf_count == 1

    def test_register_poi(self):
        mem = self._make_memory()
        poi = PointOfInterest(
            poi_type="bench",
            position=[10.0, 0.0, -20.0],
            attributes={"covered": True, "wheelchair": True},
        )
        artifact = mem.register_poi(poi)

        assert artifact.artifact_type == "poi"
        assert "bench" in artifact.keywords

    def test_register_route(self):
        mem = self._make_memory()
        route = RouteSegment(
            positions=[[0, 0, 0], [1, 0, 0], [2, 0, -1]],
            detected_objects=["bench", "stop sign"],
            hazards=[{"hazard_type": "curb"}],
            distance_meters=3.0,
            duration_seconds=120.0,
        )
        artifact = mem.register_route(route)

        assert artifact.artifact_type == "route-segment"
        assert "bench" in artifact.keywords
        assert "curb" in artifact.keywords

    def test_duplicate_detection(self):
        mem = self._make_memory()
        hazard = HazardMarker(hazard_type="curb", position=[0, 0, 0])

        a1 = mem.register_hazard(hazard, confidence=0.5)
        a2 = mem.register_hazard(hazard, confidence=0.8)

        # Should be same artifact, updated confidence
        assert a1.sha256 == a2.sha256
        assert a2.confidence == 0.8
        assert len(mem.artifacts) == 1

    def test_merkle_proof_for_artifact(self):
        mem = self._make_memory()

        for i in range(5):
            mem.register_hazard(HazardMarker(
                hazard_type=f"type-{i}",
                position=[float(i), 0, 0],
            ))

        # Get proof for the third artifact
        artifacts = list(mem.artifacts.values())
        proof = mem.proof_for(artifacts[2].sha256)

        assert proof is not None
        assert mem.verify_proof(proof)

    def test_peer_geometry_low_confidence(self):
        mem = self._make_memory()
        peer_data = {"hazard_type": "stairs_up", "step_count": 4}

        artifact = mem.register_peer_geometry(peer_data)
        assert artifact.confidence == 0.3  # Peer data starts low
        assert artifact.source == "peer"

    def test_promote_peer_data(self):
        mem = self._make_memory()
        peer_data = {"hazard_type": "stairs_up", "step_count": 4}

        artifact = mem.register_peer_geometry(peer_data)
        assert artifact.confidence == 0.3

        # Local sensors confirm → promote
        mem.promote_peer_data(artifact.sha256, 0.85)
        assert mem.artifacts[artifact.sha256].confidence == 0.85

    def test_search_by_keyword(self):
        mem = self._make_memory()
        mem.register_hazard(HazardMarker(hazard_type="stairs_down", position=[0, 0, 0]))
        mem.register_hazard(HazardMarker(hazard_type="curb", position=[5, 0, 0]))
        mem.register_poi(PointOfInterest(poi_type="bench", position=[10, 0, 0]))

        results = mem.search("stairs")
        assert len(results) == 1
        assert results[0].data["hazard_type"] == "stairs_down"

        results = mem.search("bench")
        assert len(results) == 1

    def test_by_type(self):
        mem = self._make_memory()
        mem.register_hazard(HazardMarker(hazard_type="curb", position=[0, 0, 0]))
        mem.register_poi(PointOfInterest(poi_type="bench", position=[5, 0, 0]))
        mem.register_poi(PointOfInterest(poi_type="bathroom", position=[10, 0, 0]))

        hazards = mem.by_type(SpatialArtifactType.HAZARD_MARKER)
        assert len(hazards) == 1

        pois = mem.by_type(SpatialArtifactType.POI)
        assert len(pois) == 2

    def test_exportable_hazards(self):
        mem = self._make_memory()
        mem.register_hazard(HazardMarker(hazard_type="stairs_down", position=[0, 0, 0]), confidence=0.9)
        mem.register_hazard(HazardMarker(hazard_type="curb", position=[5, 0, 0]), confidence=0.4)

        exports = mem.exportable_hazards(min_confidence=0.6)
        assert len(exports) == 1
        assert exports[0]["type"] == "stairs_down"
        # No raw positions in export (privacy)
        assert "position" not in exports[0]

    def test_stats(self):
        mem = self._make_memory()
        mem.register_hazard(HazardMarker(hazard_type="curb", position=[0, 0, 0]))
        mem.register_poi(PointOfInterest(poi_type="bench", position=[5, 0, 0]))

        stats = mem.stats()
        assert stats["total_artifacts"] == 2
        assert stats["merkle_leaves"] == 2
        assert stats["merkle_root"] is not None

    def test_persistence(self):
        tmp = Path(tempfile.mkdtemp())
        mem1 = SpatialMemory(tmp)
        mem1.register_hazard(HazardMarker(hazard_type="stairs_up", position=[0, 0, 0]))
        root1 = mem1.merkle_root

        # Reload from disk
        mem2 = SpatialMemory(tmp)
        assert len(mem2.artifacts) == 1
        assert mem2.merkle_root == root1

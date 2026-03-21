"""
Spatial memory extension for Engram — stores and indexes spatial artifacts
from Spot (LiDAR navigation app) and other spatial data sources.

Artifact types:
  - route-segment: sequence of positions + detected objects + hazards
  - room-scan: RoomPlan output (walls, doors, stairs, furniture)
  - hazard-marker: ground hazard (stairs, curb, drop-off)
  - poi: point of interest (bench, bathroom, water fountain)
  - peer-geometry: NSP-wrapped geometry from another device

Each artifact gets:
  - SHA-256 hash (integrity)
  - Merkle tree leaf (selective disclosure)
  - Keywords for semantic search
  - Tier placement (hot → warm → cold → frozen)
  - Optional encryption via Engram's existing PQ envelope

Spatial search:
  - By keyword: "stairs near oak street"
  - By type: all hazard markers
  - By proximity: within N meters of a position (H3 grid index)
  - By confidence: Cs score threshold
"""

from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from .merkle import MerkleTree, MerkleProof, rollup_from_hashes
from .metadata import MetadataStore, ArtifactMeta, Tier


class SpatialArtifactType(str, Enum):
    ROUTE_SEGMENT = "route-segment"
    ROOM_SCAN = "room-scan"
    HAZARD_MARKER = "hazard-marker"
    POI = "poi"
    PEER_GEOMETRY = "peer-geometry"
    OBJECT_POSITION = "object-position"


@dataclass
class SpatialArtifact:
    """A single spatial memory artifact."""
    artifact_id: str
    artifact_type: str              # SpatialArtifactType value
    sha256: str                     # integrity hash
    created_at: float               # unix timestamp
    last_confirmed: float           # last time sensors verified this
    confidence: float               # Cs score (0-1)
    keywords: list[str]             # for semantic search
    data: dict                      # the actual spatial data (flexible schema)

    # Peer sharing metadata
    source: str = "local"           # "local" | "peer" | "osm"
    peer_confirmations: int = 0     # how many peers have confirmed this
    merkle_leaf_index: int = -1     # position in the Merkle tree

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> SpatialArtifact:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class RouteSegment:
    """A recorded walking route segment."""
    positions: list[list[float]]    # [[x, y, z], ...]
    detected_objects: list[str]     # labels seen along route
    hazards: list[dict]             # hazard markers along route
    distance_meters: float = 0.0
    duration_seconds: float = 0.0
    walk_count: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HazardMarker:
    """A ground hazard detected by sensors."""
    hazard_type: str                # stairs_up, stairs_down, curb, drop_off, slope
    position: list[float]           # [x, y, z]
    step_count: int = 0             # for stairs
    height_meters: float = 0.0      # elevation change
    direction: str = "ahead"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PointOfInterest:
    """A known location — bench, bathroom, water fountain."""
    poi_type: str                   # bench, bathroom, water, cafe, shelter
    position: list[float]           # [x, y, z] or [lat, lon]
    attributes: dict = field(default_factory=dict)  # wheelchair, covered, fee, etc.

    def to_dict(self) -> dict:
        return asdict(self)


class SpatialMemory:
    """
    Manages spatial artifacts with Merkle tree integrity and tiered storage.

    This is the bridge between Spot (Swift, on-device) and Engram (Python, compression).
    Spot exports spatial data as JSON → Engram ingests, indexes, compresses, and
    builds the Merkle tree for integrity verification and selective peer sharing.
    """

    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.artifacts_dir = storage_dir / "spatial"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.tree = MerkleTree()
        self.artifacts: dict[str, SpatialArtifact] = {}

        self._tree_path = self.artifacts_dir / "merkle-tree.json"
        self._registry_path = self.artifacts_dir / "spatial-registry.json"

        self._load()

    # ── Registration ──

    def register(
        self,
        artifact_type: SpatialArtifactType,
        data: dict,
        confidence: float = 1.0,
        keywords: Optional[list[str]] = None,
        source: str = "local",
    ) -> SpatialArtifact:
        """Register a new spatial artifact. Hashes it, adds to Merkle tree, indexes keywords."""

        # Serialize and hash
        data_bytes = json.dumps(data, sort_keys=True).encode()
        sha256 = hashlib.sha256(data_bytes).hexdigest()

        # Check for duplicate
        if sha256 in self.artifacts:
            # Update confidence and confirmation count
            existing = self.artifacts[sha256]
            existing.last_confirmed = time.time()
            existing.confidence = max(existing.confidence, confidence)
            if source == "peer":
                existing.peer_confirmations += 1
            self._save()
            return existing

        # Extract keywords from data
        auto_keywords = self._extract_keywords(artifact_type, data)
        all_keywords = list(set((keywords or []) + auto_keywords))

        # Create artifact
        artifact = SpatialArtifact(
            artifact_id=sha256[:16],
            artifact_type=artifact_type.value,
            sha256=sha256,
            created_at=time.time(),
            last_confirmed=time.time(),
            confidence=confidence,
            keywords=all_keywords,
            data=data,
            source=source,
            peer_confirmations=1 if source == "peer" else 0,
        )

        # Add to Merkle tree
        leaf_index = self.tree.add(data_bytes)
        artifact.merkle_leaf_index = leaf_index

        # Store
        self.artifacts[sha256] = artifact
        self._save()

        return artifact

    def register_route(self, route: RouteSegment, confidence: float = 1.0, keywords: Optional[list[str]] = None) -> SpatialArtifact:
        return self.register(SpatialArtifactType.ROUTE_SEGMENT, route.to_dict(), confidence, keywords)

    def register_hazard(self, hazard: HazardMarker, confidence: float = 1.0) -> SpatialArtifact:
        keywords = [hazard.hazard_type, hazard.direction]
        return self.register(SpatialArtifactType.HAZARD_MARKER, hazard.to_dict(), confidence, keywords)

    def register_poi(self, poi: PointOfInterest, confidence: float = 1.0) -> SpatialArtifact:
        keywords = [poi.poi_type] + list(poi.attributes.keys())
        return self.register(SpatialArtifactType.POI, poi.to_dict(), confidence, keywords)

    def register_peer_geometry(self, data: dict, confidence: float = 0.3) -> SpatialArtifact:
        """Register geometry from a peer device. Starts at low confidence (Cs = 0.3)."""
        return self.register(SpatialArtifactType.PEER_GEOMETRY, data, confidence, source="peer")

    # ── Merkle Proofs ──

    def proof_for(self, sha256: str) -> Optional[MerkleProof]:
        """Generate a Merkle proof for an artifact by its hash."""
        artifact = self.artifacts.get(sha256)
        if not artifact or artifact.merkle_leaf_index < 0:
            return None
        return self.tree.proof(artifact.merkle_leaf_index)

    def verify_proof(self, proof: MerkleProof) -> bool:
        """Verify a Merkle proof against the current tree root."""
        return MerkleTree.verify(proof)

    @property
    def merkle_root(self) -> Optional[str]:
        """Current Merkle root hash (hex)."""
        return self.tree.root_hex

    # ── Rollup ──

    def rollup_route(self, artifacts: list[SpatialArtifact]) -> tuple[MerkleTree, str]:
        """Batch multiple route segments into one Merkle tree for efficient signing."""
        hashes = [a.sha256 for a in artifacts]
        return rollup_from_hashes(hashes)

    # ── Search ──

    def search(self, query: str) -> list[SpatialArtifact]:
        """Search spatial artifacts by keyword."""
        query_lower = query.lower()
        terms = query_lower.split()
        results = []
        for artifact in self.artifacts.values():
            keywords_lower = [k.lower() for k in artifact.keywords]
            if any(term in kw for term in terms for kw in keywords_lower):
                results.append(artifact)
        return sorted(results, key=lambda a: a.confidence, reverse=True)

    def by_type(self, artifact_type: SpatialArtifactType) -> list[SpatialArtifact]:
        """Get all artifacts of a given type."""
        return [a for a in self.artifacts.values() if a.artifact_type == artifact_type.value]

    def by_confidence(self, min_cs: float) -> list[SpatialArtifact]:
        """Get artifacts above a confidence threshold."""
        return [a for a in self.artifacts.values() if a.confidence >= min_cs]

    def hazards(self) -> list[SpatialArtifact]:
        """Get all hazard markers."""
        return self.by_type(SpatialArtifactType.HAZARD_MARKER)

    def routes(self) -> list[SpatialArtifact]:
        """Get all route segments."""
        return self.by_type(SpatialArtifactType.ROUTE_SEGMENT)

    def pois(self) -> list[SpatialArtifact]:
        """Get all points of interest."""
        return self.by_type(SpatialArtifactType.POI)

    # ── Peer Sharing ──

    def promote_peer_data(self, sha256: str, new_confidence: float) -> bool:
        """Promote peer-shared data to higher confidence after local sensor confirmation."""
        artifact = self.artifacts.get(sha256)
        if not artifact:
            return False
        artifact.confidence = max(artifact.confidence, new_confidence)
        artifact.last_confirmed = time.time()
        self._save()
        return True

    def exportable_hazards(self, min_confidence: float = 0.6) -> list[dict]:
        """
        Export hazard data for peer sharing.
        Only exports semantic summaries — never raw geometry.
        Only exports data above confidence threshold.
        """
        result = []
        for artifact in self.hazards():
            if artifact.confidence >= min_confidence:
                # Semantic summary only (no raw positions for privacy)
                summary = {
                    "type": artifact.data.get("hazard_type"),
                    "step_count": artifact.data.get("step_count", 0),
                    "height_meters": artifact.data.get("height_meters", 0),
                    "direction": artifact.data.get("direction"),
                    "confidence": artifact.confidence,
                    "sha256": artifact.sha256,
                }
                result.append(summary)
        return result

    # ── Stats ──

    def stats(self) -> dict:
        """Summary statistics."""
        by_type: dict[str, int] = {}
        for a in self.artifacts.values():
            by_type[a.artifact_type] = by_type.get(a.artifact_type, 0) + 1

        peer_count = sum(1 for a in self.artifacts.values() if a.source == "peer")

        return {
            "total_artifacts": len(self.artifacts),
            "by_type": by_type,
            "peer_shared": peer_count,
            "merkle_root": self.merkle_root,
            "merkle_leaves": self.tree.leaf_count,
        }

    # ── Keywords ──

    def _extract_keywords(self, artifact_type: SpatialArtifactType, data: dict) -> list[str]:
        """Auto-extract searchable keywords from spatial data."""
        keywords = [artifact_type.value]

        if artifact_type == SpatialArtifactType.HAZARD_MARKER:
            if "hazard_type" in data:
                keywords.append(data["hazard_type"])
            if "direction" in data:
                keywords.append(data["direction"])

        elif artifact_type == SpatialArtifactType.ROUTE_SEGMENT:
            keywords.extend(data.get("detected_objects", []))
            for h in data.get("hazards", []):
                if "hazard_type" in h:
                    keywords.append(h["hazard_type"])

        elif artifact_type == SpatialArtifactType.POI:
            if "poi_type" in data:
                keywords.append(data["poi_type"])
            keywords.extend(data.get("attributes", {}).keys())

        elif artifact_type == SpatialArtifactType.ROOM_SCAN:
            keywords.extend(["indoor", "room"])
            if "door_count" in data:
                keywords.append("door")
            if "stair_count" in data:
                keywords.append("stairs")

        return list(set(keywords))

    # ── Persistence ──

    def _save(self) -> None:
        # Save registry (atomic write)
        from .fileutil import atomic_write_text
        registry = {k: v.to_dict() for k, v in self.artifacts.items()}
        atomic_write_text(self._registry_path, json.dumps(registry, indent=2))

        # Save Merkle tree (already uses atomic write internally)
        self.tree.save(str(self._tree_path))

    def _load(self) -> None:
        # Load registry
        if self._registry_path.exists():
            with open(self._registry_path) as f:
                data = json.load(f)
            for key, val in data.items():
                self.artifacts[key] = SpatialArtifact.from_dict(val)

        # Load Merkle tree
        if self._tree_path.exists():
            self.tree = MerkleTree.load(str(self._tree_path))

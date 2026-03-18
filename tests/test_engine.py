"""Integration tests for the tiering engine."""

import time
from pathlib import Path

import pytest

from src.config import EngineConfig, ScanTarget, TierPolicy
from src.engine import TieringEngine
from src.metadata import Tier


@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    """Create a directory with test artifacts."""
    d = tmp_path / "artifacts"
    d.mkdir()
    for i in range(5):
        f = d / f"session-{i}.jsonl"
        # Write enough repetitive content to be compressible
        lines = [
            f'{{"turn": {j}, "role": "assistant", "text": "response {j} in session {i}"}}\n'
            for j in range(200)
        ]
        f.write_text("".join(lines))
    return d


@pytest.fixture
def engine_config(tmp_path: Path, artifact_dir: Path) -> EngineConfig:
    return EngineConfig(
        scan_targets=[
            ScanTarget(path=str(artifact_dir), pattern="*.jsonl", description="test")
        ],
        tier_policy=TierPolicy(
            hot_to_warm_age_hours=0,   # Immediate for testing
            hot_to_warm_idle_hours=0,
            warm_to_cold_age_hours=0,
            warm_to_cold_idle_hours=0,
            min_file_size_bytes=100,
            keep_originals=False,
        ),
        metadata_dir=str(tmp_path / "meta"),
        dry_run=False,
    )


class TestTieringEngine:
    def test_scan_discovers_files(self, engine_config: EngineConfig, artifact_dir: Path):
        engine = TieringEngine(engine_config)
        found = engine.scan()
        assert len(found) == 5
        assert all(f.suffix == ".jsonl" for f in found)

    def test_dry_run_no_changes(self, engine_config: EngineConfig, artifact_dir: Path):
        engine_config.dry_run = True
        engine = TieringEngine(engine_config)
        actions = engine.run()
        # Should report actions but files untouched
        assert len(actions) > 0
        assert all(a.dry_run for a in actions)
        # Original files still exist
        assert len(list(artifact_dir.glob("*.jsonl"))) == 5

    def test_hot_to_warm_transition(self, engine_config: EngineConfig, artifact_dir: Path):
        engine = TieringEngine(engine_config)

        # First run: scan and register as hot
        discovered = engine.scan()
        engine.register_all(discovered)

        # Artificially age all artifacts
        for meta in engine.metadata.all_artifacts():
            meta.created_at = time.time() - (72 * 3600)
            meta.last_accessed = time.time() - (48 * 3600)
        engine.metadata.save()

        # Run tiering
        actions = engine.evaluate_and_tier()
        warm_actions = [a for a in actions if a.to_tier == "warm"]
        assert len(warm_actions) == 5

        # Check compression happened
        for a in warm_actions:
            assert a.ratio > 1.0
            assert a.new_size < a.original_size

    def test_warm_to_cold_transition(self, artifact_dir: Path, tmp_path: Path):
        # Use separate thresholds so warm and cold don't both trigger in one pass
        config = EngineConfig(
            scan_targets=[
                ScanTarget(path=str(artifact_dir), pattern="*.jsonl", description="test")
            ],
            tier_policy=TierPolicy(
                hot_to_warm_age_hours=0,
                hot_to_warm_idle_hours=0,
                warm_to_cold_age_hours=100,   # Cold requires 100h age
                warm_to_cold_idle_hours=100,
                min_file_size_bytes=100,
                keep_originals=False,
            ),
            metadata_dir=str(tmp_path / "meta2"),
            dry_run=False,
        )
        engine = TieringEngine(config)

        # Scan and register
        discovered = engine.scan()
        engine.register_all(discovered)

        # Age enough for warm but not cold, then tier
        for meta in engine.metadata.all_artifacts():
            meta.created_at = time.time() - (72 * 3600)
            meta.last_accessed = time.time() - (48 * 3600)
        engine.metadata.save()
        actions1 = engine.evaluate_and_tier()
        warm_actions = [a for a in actions1 if a.to_tier == "warm"]
        assert len(warm_actions) == 5

        # Now age warm artifacts past the cold threshold
        for meta in engine.metadata.all_artifacts():
            meta.created_at = time.time() - (400 * 3600)
            meta.last_accessed = time.time() - (400 * 3600)
        engine.metadata.save()

        # Run again — should trigger warm -> cold
        actions2 = engine.evaluate_and_tier()
        cold_actions = [a for a in actions2 if a.to_tier == "cold"]
        assert len(cold_actions) == 5

    def test_recall_from_warm(self, engine_config: EngineConfig, artifact_dir: Path):
        engine = TieringEngine(engine_config)

        # Get original content
        first_file = sorted(artifact_dir.glob("*.jsonl"))[0]
        original_content = first_file.read_bytes()

        # Scan, age, and tier
        discovered = engine.scan()
        engine.register_all(discovered)
        for meta in engine.metadata.all_artifacts():
            meta.created_at = time.time() - (72 * 3600)
            meta.last_accessed = time.time() - (48 * 3600)
        engine.metadata.save()
        engine.evaluate_and_tier()

        # Recall the first file
        recalled = engine.recall(first_file)
        assert recalled is not None
        assert recalled.exists()
        # Pipeline applies minification (whitespace removal) so content
        # is semantically equivalent but not byte-identical.
        # Verify all JSON entries are preserved:
        import json
        original_lines = [json.loads(l) for l in original_content.split(b"\n") if l.strip()]
        recalled_lines = [json.loads(l) for l in recalled.read_bytes().split(b"\n") if l.strip()]
        assert len(recalled_lines) == len(original_lines)
        for orig, recv in zip(original_lines, recalled_lines):
            assert orig == recv

    def test_status_report(self, engine_config: EngineConfig, artifact_dir: Path):
        engine = TieringEngine(engine_config)
        engine.run()
        status = engine.status()
        assert "total_artifacts" in status
        assert "hot_count" in status
        assert "warm_count" in status
        assert "cold_count" in status

    def test_empty_scan(self, tmp_path: Path):
        config = EngineConfig(
            scan_targets=[
                ScanTarget(path=str(tmp_path / "empty"), pattern="*.jsonl")
            ],
            metadata_dir=str(tmp_path / "meta"),
        )
        engine = TieringEngine(config)
        actions = engine.run()
        assert len(actions) == 0

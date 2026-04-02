"""
SIEMPLE-AI schema validator for Myelin8.

Validates fact and episode artifacts against the YAML schemas defined in
SIEMPLE-AI's schemas/ directory. Uses jsonschema for validation.

Schema files referenced:
  - fact.schema.yaml: semantic memory facts
  - episode.schema.yaml: episodic memory events

This module requires the [governance] optional dependency:
  pip install myelin8[governance]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("myelin8.schema_validator")

# Default SIEMPLE-AI schemas directory (sibling repo)
DEFAULT_SCHEMAS_DIR = Path(__file__).parent.parent.parent / "SIEMPLE-AI" / "schemas"


@dataclass
class ValidationResult:
    """Result of validating an artifact against a schema."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    schema_used: Optional[str] = None

    def to_dict(self) -> dict:
        return {"valid": self.valid, "errors": self.errors, "schema_used": self.schema_used}


class SchemaValidator:
    """Validates artifacts against SIEMPLE-AI YAML schemas.

    Loads schemas once at init, validates many artifacts.
    Falls back to permissive mode (warn, don't block) if schemas or
    dependencies are missing.
    """

    def __init__(self, schemas_dir: Optional[Path] = None) -> None:
        self._schemas_dir = schemas_dir or DEFAULT_SCHEMAS_DIR
        self._fact_schema: Optional[dict] = None
        self._episode_schema: Optional[dict] = None
        self._loaded = False
        self._permissive = False  # True if schemas/deps missing

    def _load_schemas(self) -> None:
        """Load YAML schemas from disk. Called lazily on first validate()."""
        if self._loaded:
            return
        self._loaded = True

        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("pyyaml not installed. Schema validation in permissive mode.")
            self._permissive = True
            return

        fact_path = Path(self._schemas_dir) / "fact.schema.yaml"
        episode_path = Path(self._schemas_dir) / "episode.schema.yaml"

        if fact_path.exists():
            with open(fact_path) as f:
                self._fact_schema = yaml.safe_load(f)
        else:
            logger.warning("fact.schema.yaml not found at %s. Permissive mode.", fact_path)
            self._permissive = True

        if episode_path.exists():
            with open(episode_path) as f:
                self._episode_schema = yaml.safe_load(f)
        else:
            logger.warning("episode.schema.yaml not found at %s.", episode_path)

    def _validate_against_schema(self, artifact: dict, schema: dict, schema_name: str) -> ValidationResult:
        """Validate artifact dict against a JSON Schema."""
        try:
            import jsonschema  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("jsonschema not installed. Permissive validation.")
            return ValidationResult(valid=True, errors=["jsonschema not installed — skipped"], schema_used=schema_name)

        errors: list[str] = []
        validator = jsonschema.Draft7Validator(schema)
        for error in validator.iter_errors(artifact):
            path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
            errors.append(f"{path}: {error.message}")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            schema_used=schema_name,
        )

    def validate_fact(self, artifact: dict) -> ValidationResult:
        """Validate an artifact against fact.schema.yaml."""
        self._load_schemas()
        if self._permissive or self._fact_schema is None:
            return ValidationResult(valid=True, errors=["permissive mode — schema not loaded"], schema_used="fact")
        return self._validate_against_schema(artifact, self._fact_schema, "fact.schema.yaml")

    def validate_episode(self, artifact: dict) -> ValidationResult:
        """Validate an artifact against episode.schema.yaml."""
        self._load_schemas()
        if self._permissive or self._episode_schema is None:
            return ValidationResult(valid=True, errors=["permissive mode — schema not loaded"], schema_used="episode")
        return self._validate_against_schema(artifact, self._episode_schema, "episode.schema.yaml")

    def validate(self, artifact: dict, schema_type: str = "fact") -> ValidationResult:
        """Validate an artifact against the appropriate schema."""
        if schema_type == "fact":
            return self.validate_fact(artifact)
        elif schema_type == "episode":
            return self.validate_episode(artifact)
        return ValidationResult(valid=False, errors=[f"Unknown schema type: {schema_type}"])

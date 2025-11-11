"""Utilities for loading OpenAPI/Swagger specifications."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None


class OpenAPISpecLoader:
    """Load OpenAPI/Swagger specifications from JSON or YAML files."""

    def __init__(self, spec_path: str | Path) -> None:
        self.spec_path = Path(spec_path)

    def load(self) -> Dict[str, Any]:
        """Load and parse the specification file.

        Returns:
            Parsed OpenAPI specification as a dictionary.

        Raises:
            FileNotFoundError: If the spec file does not exist.
            ValueError: If the spec file cannot be parsed.
        """

        if not self.spec_path.exists():
            raise FileNotFoundError(f"Spec file not found: {self.spec_path}")

        data = self.spec_path.read_text(encoding="utf-8")
        suffix = self.spec_path.suffix.lower()
        if suffix in {".json", ".swagger"}:
            return json.loads(data)
        if suffix in {".yaml", ".yml"}:
            if yaml is None:
                raise ValueError(
                    "PyYAML is required to parse YAML specifications. Install pyyaml."
                )
            return yaml.safe_load(data)
        # attempt to auto-detect JSON or YAML
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            if yaml is None:
                raise ValueError(
                    "Unable to parse specification; install pyyaml for YAML support."
                )
            return yaml.safe_load(data)

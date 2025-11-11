"""Test case generation from OpenAPI specs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class APITestCase:
    """Represents a single API test case."""

    method: str
    path: str
    requires_auth: bool
    security_schemes: Optional[List[str]]
    parameters: Dict[str, Any]

    def url(self, base_url: str) -> str:
        return f"{base_url.rstrip('/')}/{self.path.lstrip('/')}"


class TestCaseGenerator:
    """Generate API test cases from an OpenAPI specification."""

    def __init__(self, spec: Dict[str, Any]) -> None:
        self.spec = spec

    def generate(self) -> Iterable[APITestCase]:
        paths = self.spec.get("paths", {})
        components = self.spec.get("components", {})
        global_security = self.spec.get("security")

        for raw_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    continue

                security = operation.get("security", global_security)
                requires_auth = bool(security)
                security_schemes = None
                if requires_auth and isinstance(security, list):
                    security_schemes = [
                        next(iter(item.keys()))
                        for item in security
                        if isinstance(item, dict) and item
                    ]

                parameters = self._extract_parameters(operation, components)
                yield APITestCase(
                    method=method.upper(),
                    path=raw_path,
                    requires_auth=requires_auth,
                    security_schemes=security_schemes,
                    parameters=parameters,
                )

    def _extract_parameters(
        self, operation: Dict[str, Any], components: Dict[str, Any]
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        for param in operation.get("parameters", []):
            name = param.get("name")
            default = param.get("example") or param.get("default")
            if name and default is not None:
                params[name] = default
        request_body = operation.get("requestBody", {})
        if not isinstance(request_body, dict):
            return params
        content = request_body.get("content", {})
        if not isinstance(content, dict):
            return params
        for media_type, media_details in content.items():
            schema = media_details.get("schema", {})
            example = media_details.get("example") or media_details.get("examples")
            if example:
                params["body"] = example
                break
            ref = schema.get("$ref")
            if ref:
                resolved = self._resolve_ref(ref, components)
                if resolved and "example" in resolved:
                    params["body"] = resolved["example"]
                    break
        return params

    def _resolve_ref(self, ref: str, components: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not ref.startswith("#/components/"):
            return None
        parts = ref.lstrip("#/").split("/")
        current: Any = self.spec
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        if isinstance(current, dict):
            return current
        return None

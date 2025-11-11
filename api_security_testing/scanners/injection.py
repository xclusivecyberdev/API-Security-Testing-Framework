"""Scanner for injection vulnerabilities."""

from __future__ import annotations

from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase


INJECTION_PAYLOADS = {
    "sql": "' OR '1'='1",
    "command": "$(id)",
    "nosql": "{\"$ne\": null}",
    "xss": "<script>alert('xss')</script>",
}


class InjectionScanner(Scanner):
    name = "injection"
    description = "Attempts to inject malicious payloads into parameters and body."

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def scan(
        self,
        test_case: APITestCase,
        session: requests.Session,
        base_url: str,
        context: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> ScanResult:
        url = test_case.url(base_url)
        vulnerable_payloads = []
        for payload_name, payload in INJECTION_PAYLOADS.items():
            params = {**test_case.parameters}
            if params:
                params = {k: payload if k != "body" else payload for k in params}
            data = None
            json_data = None
            headers = context.get("privileged_headers") if context else None
            if "body" in params:
                body = params.pop("body")
                if isinstance(body, dict):
                    json_data = {k: payload for k in body}
                else:
                    data = payload
            try:
                response = session.request(
                    test_case.method,
                    url,
                    params=params if test_case.method == "GET" else None,
                    data=data,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                return self._build_result(
                    False,
                    risk="Medium",
                    details={"error": str(exc)},
                    description="Error occurred during injection check",
                )
            if any(token in response.text.lower() for token in ["syntax", "sql", "exception", "trace"]):
                vulnerable_payloads.append(payload_name)
        if vulnerable_payloads:
            return self._build_result(
                False,
                risk="High",
                details={"payloads": ", ".join(vulnerable_payloads)},
                description="Potential injection vulnerability detected",
            )
        return self._build_result(True, description="No injection indicators detected")

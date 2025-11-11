"""Scanner for OWASP API Security Top 10 issues."""

from __future__ import annotations

from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase

SENSITIVE_KEYWORDS = [
    "password",
    "secret",
    "token",
    "apikey",
    "private",
]

ERROR_INDICATORS = [
    "stack trace",
    "exception",
    "traceback",
    "error on line",
]


class OWASPTop10Scanner(Scanner):
    name = "owasp_api_top10"
    description = "Performs heuristic checks for OWASP API Security Top 10 vulnerabilities."

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
        headers = None
        if context:
            headers = context.get("privileged_headers") or context.get("unprivileged_headers")
        try:
            response = session.request(
                test_case.method,
                url,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return self._build_result(
                False,
                risk="Medium",
                details={"error": str(exc)},
                description="Error occurred during OWASP Top 10 heuristic checks",
            )

        body_lower = response.text.lower()
        exposed_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in body_lower]
        error_keywords = [kw for kw in ERROR_INDICATORS if kw in body_lower]

        if exposed_keywords or error_keywords:
            issues = []
            if exposed_keywords:
                issues.append(f"Sensitive data exposed: {', '.join(exposed_keywords)}")
            if error_keywords:
                issues.append(f"Verbose error messages: {', '.join(error_keywords)}")
            return self._build_result(
                False,
                risk="High",
                details={"issues": "; ".join(issues)},
                description="Potential OWASP API Top 10 issues detected",
            )
        return self._build_result(True, description="No OWASP Top 10 indicators detected")

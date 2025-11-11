"""Scanner for security misconfigurations."""

from __future__ import annotations

from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase

REQUIRED_HEADERS = {
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
}


class SecurityMisconfigurationScanner(Scanner):
    name = "security_misconfiguration"
    description = "Checks for missing security headers and configuration issues."

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
        headers = context.get("privileged_headers") if context else None
        try:
            response = session.request(
                "GET", url, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            return self._build_result(
                False,
                risk="Medium",
                details={"error": str(exc)},
                description="Error occurred during misconfiguration check",
            )

        missing = [header for header in REQUIRED_HEADERS if header not in response.headers]
        if missing:
            return self._build_result(
                False,
                risk="Medium",
                details={"missing_headers": ", ".join(missing)},
                description="Security headers missing",
            )
        return self._build_result(True, description="Security headers present")

"""Scanner for broken authentication vulnerabilities."""

from __future__ import annotations

from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase


class BrokenAuthenticationScanner(Scanner):
    name = "broken_authentication"
    description = "Checks for broken authentication by accessing endpoints without credentials."

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def scan(
        self,
        test_case: APITestCase,
        session: requests.Session,
        base_url: str,
        context: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        if not test_case.requires_auth:
            return self._build_result(True, description="Endpoint does not require authentication")

        url = test_case.url(base_url)
        try:
            response = session.request(test_case.method, url, timeout=self.timeout)
        except requests.RequestException as exc:
            return self._build_result(
                False,
                risk="High",
                details={"error": str(exc)},
                description="Error occurred during authentication check",
            )

        if response.status_code in {401, 403}:
            return self._build_result(True, description="Authentication enforced")

        return self._build_result(
            False,
            risk="High",
            details={
                "status_code": str(response.status_code),
                "reason": response.reason,
            },
            description="Endpoint allowed access without authentication",
        )

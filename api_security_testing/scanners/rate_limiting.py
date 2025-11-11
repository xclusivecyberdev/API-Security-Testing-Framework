"""Scanner for rate limiting vulnerabilities."""

from __future__ import annotations

import time
from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase


class RateLimitingScanner(Scanner):
    name = "rate_limiting"
    description = "Checks if the API enforces rate limiting."

    def __init__(self, timeout: int = 10, request_count: int = 5) -> None:
        self.timeout = timeout
        self.request_count = request_count

    def scan(
        self,
        test_case: APITestCase,
        session: requests.Session,
        base_url: str,
        context: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> ScanResult:
        url = test_case.url(base_url)
        headers = context.get("privileged_headers") if context else None
        status_codes = []
        for _ in range(self.request_count):
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
                    description="Error occurred during rate limiting check",
                )
            status_codes.append(response.status_code)
            time.sleep(0.1)
        if 429 in status_codes:
            return self._build_result(True, description="Rate limiting enforced")
        return self._build_result(
            False,
            risk="Medium",
            details={"status_codes": ", ".join(map(str, status_codes))},
            description="No evidence of rate limiting",
        )

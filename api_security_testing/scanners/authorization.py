"""Scanner for broken authorization vulnerabilities."""

from __future__ import annotations

from typing import Dict, Optional

from .._requests import requests

from .base import ScanResult, Scanner
from ..test_case_generator import APITestCase


class BrokenAuthorizationScanner(Scanner):
    name = "broken_authorization"
    description = "Checks if low-privileged users can access protected resources."

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def scan(
        self,
        test_case: APITestCase,
        session: requests.Session,
        base_url: str,
        context: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> ScanResult:
        if not test_case.requires_auth:
            return self._build_result(True, description="Endpoint is public")

        if not context or "privileged_headers" not in context or "unprivileged_headers" not in context:
            return self._build_result(
                False,
                risk="Medium",
                description="Authorization context missing",
            )

        url = test_case.url(base_url)
        try:
            privileged = session.request(
                test_case.method,
                url,
                headers=context["privileged_headers"],
                timeout=self.timeout,
            )
            unprivileged = session.request(
                test_case.method,
                url,
                headers=context["unprivileged_headers"],
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return self._build_result(
                False,
                risk="High",
                details={"error": str(exc)},
                description="Error occurred during authorization check",
            )

        if privileged.status_code >= 400:
            return self._build_result(
                False,
                risk="Medium",
                details={"status_code": str(privileged.status_code)},
                description="Privileged access failed",
            )

        if unprivileged.status_code in {401, 403}:
            return self._build_result(True, description="Authorization enforced")

        if unprivileged.status_code == privileged.status_code:
            return self._build_result(
                False,
                risk="High",
                details={"status_code": str(unprivileged.status_code)},
                description="Unprivileged user received same response as privileged user",
            )

        return self._build_result(
            True,
            description="Authorization appears enforced with differing responses",
            details={"privileged_status": str(privileged.status_code), "unprivileged_status": str(unprivileged.status_code)},
        )

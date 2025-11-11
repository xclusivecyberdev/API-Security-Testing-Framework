"""Tests for the API security testing framework."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List

import pytest

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api_security_testing import (
    APISecurityTestRunner,
    OpenAPISpecLoader,
    TestCaseGenerator,
)
from api_security_testing.reporting import ReportGenerator
from api_security_testing.scanners import (
    BrokenAuthenticationScanner,
    RateLimitingScanner,
    SecurityMisconfigurationScanner,
)


class MockResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Dict[str, str] | None = None,
        reason: str = "OK",
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.reason = reason


class MockSession:
    def __init__(self, responses: Iterable[MockResponse]) -> None:
        self._responses = list(responses)
        self.requests: List[Dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs):  # pragma: no cover - simple pass through
        if not self._responses:
            raise AssertionError("No more mock responses available")
        self.requests.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


@pytest.fixture()
def spec_path(tmp_path: Path) -> Path:
    fixture = Path(__file__).parent / "data" / "petstore.json"
    target = tmp_path / "petstore.json"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_spec_loader_reads_json(spec_path: Path) -> None:
    data = OpenAPISpecLoader(spec_path).load()
    assert data["info"]["title"] == "Sample API"


def test_test_case_generator_creates_cases(spec_path: Path) -> None:
    spec = OpenAPISpecLoader(spec_path).load()
    generator = TestCaseGenerator(spec)
    cases = list(generator.generate())
    assert len(cases) == 3
    assert any(case.path == "/pets" and case.method == "GET" for case in cases)


def test_runner_produces_report_with_mock_session(spec_path: Path) -> None:
    spec = OpenAPISpecLoader(spec_path).load()
    generator = TestCaseGenerator(spec)
    case = next(case for case in generator.generate() if case.path == "/pets" and case.method == "GET")

    responses = [
        MockResponse(status_code=401),  # BrokenAuthenticationScanner should pass
        MockResponse(headers={  # SecurityMisconfigurationScanner should pass
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }),
        MockResponse(status_code=200),
        MockResponse(status_code=429),  # RateLimitingScanner should detect limiting
    ]
    session = MockSession(responses)

    runner = APISecurityTestRunner(
        base_url="https://api.example.com",
        test_cases=[case],
        scanners=(
            BrokenAuthenticationScanner(),
            SecurityMisconfigurationScanner(),
            RateLimitingScanner(request_count=2),
        ),
        session=session,
        context={
            "privileged_headers": {"Authorization": "Bearer privileged"},
            "unprivileged_headers": {"Authorization": "Bearer unprivileged"},
        },
    )

    results = runner.run()
    assert len(results) == 3
    assert results[0].success  # authentication enforced
    assert results[1].success  # headers present
    assert results[2].success  # rate limiting detected

    report = ReportGenerator(results)
    report_json = json.loads(report.to_json())
    assert report_json["summary"]["total_checks"] == 3
    assert report_json["summary"]["passed"] == 3

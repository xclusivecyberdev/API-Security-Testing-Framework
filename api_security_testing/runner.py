"""Main runner for the API security testing framework."""

from __future__ import annotations

import argparse
from typing import Dict, Iterable, List, Optional, Sequence

from ._requests import requests

from .reporting import ReportGenerator
from .scanners import (
    BrokenAuthenticationScanner,
    BrokenAuthorizationScanner,
    InjectionScanner,
    OWASPTop10Scanner,
    RateLimitingScanner,
    SecurityMisconfigurationScanner,
)
from .scanners.base import ScanResult, Scanner
from .spec_loader import OpenAPISpecLoader
from .test_case_generator import APITestCase, TestCaseGenerator


DEFAULT_SCANNERS: Sequence[Scanner] = (
    BrokenAuthenticationScanner(),
    BrokenAuthorizationScanner(),
    InjectionScanner(),
    SecurityMisconfigurationScanner(),
    RateLimitingScanner(),
    OWASPTop10Scanner(),
)


class APISecurityTestRunner:
    """Run configured scanners against API endpoints."""

    def __init__(
        self,
        base_url: str,
        test_cases: Iterable[APITestCase],
        scanners: Sequence[Scanner] = DEFAULT_SCANNERS,
        session: Optional[requests.Session] = None,
        context: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        self.base_url = base_url
        self.test_cases = list(test_cases)
        self.scanners = scanners
        self.session = session or requests.Session()
        self.context = context or {}

    def run(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        for test_case in self.test_cases:
            for scanner in self.scanners:
                result = scanner.scan(test_case, self.session, self.base_url, context=self.context)
                if isinstance(result, list):  # composite scanner support
                    results.extend(result)
                else:
                    results.append(result)
        return results

    def generate_report(self) -> ReportGenerator:
        return ReportGenerator(self.run())


def parse_args(args: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run API security tests")
    parser.add_argument("spec", help="Path to OpenAPI/Swagger specification file")
    parser.add_argument("base_url", help="Base URL of the API to test")
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save the JSON report",
    )
    parser.add_argument(
        "--unprivileged-token",
        help="Token for a low-privileged user (sent as Bearer)",
    )
    parser.add_argument(
        "--privileged-token",
        help="Token for a high-privileged user (sent as Bearer)",
    )
    return parser.parse_args(args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    spec = OpenAPISpecLoader(args.spec).load()
    generator = TestCaseGenerator(spec)
    test_cases = list(generator.generate())

    context: Dict[str, Dict[str, str]] = {}
    if args.unprivileged_token:
        context["unprivileged_headers"] = {
            "Authorization": f"Bearer {args.unprivileged_token}",
        }
    if args.privileged_token:
        context["privileged_headers"] = {
            "Authorization": f"Bearer {args.privileged_token}",
        }

    runner = APISecurityTestRunner(args.base_url, test_cases, context=context)
    report = runner.generate_report()

    output = report.to_json()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

"""Base classes for scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..test_case_generator import APITestCase


@dataclass
class ScanResult:
    """Represents the result of a scanner."""

    name: str
    description: str
    risk: str
    success: bool
    details: Optional[Dict[str, str]] = None


class Scanner:
    """Base scanner class."""

    name = "base"
    description = "Base scanner"

    def scan(
        self,
        test_case: APITestCase,
        session,
        base_url: str,
        context: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        raise NotImplementedError

    def _build_result(
        self,
        success: bool,
        details: Optional[Dict[str, str]] = None,
        risk: str = "Medium",
        description: Optional[str] = None,
    ) -> ScanResult:
        return ScanResult(
            name=self.name,
            description=description or self.description,
            risk=risk,
            success=success,
            details=details,
        )


class CompositeScanner(Scanner):
    """Composite scanner that groups multiple scanners."""

    def __init__(self, scanners: List[Scanner]) -> None:
        self.scanners = scanners
        self.name = "+".join(scanner.name for scanner in scanners)
        self.description = ", ".join(scanner.description for scanner in scanners)

    def scan(
        self,
        test_case: APITestCase,
        session,
        base_url: str,
        context: Optional[Dict[str, str]] = None,
    ) -> List[ScanResult]:
        return [
            scanner.scan(test_case, session, base_url, context=context)
            for scanner in self.scanners
        ]

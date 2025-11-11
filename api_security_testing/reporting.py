"""Reporting utilities for the API security testing framework."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Dict, Iterable, List

from .scanners.base import ScanResult


class ReportGenerator:
    """Generate structured reports for scan results."""

    def __init__(self, results: Iterable[ScanResult]) -> None:
        self.results = list(results)

    def to_dict(self) -> Dict[str, object]:
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": self._build_summary(),
            "results": [asdict(result) for result in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def _build_summary(self) -> Dict[str, object]:
        total = len(self.results)
        passed = sum(1 for result in self.results if result.success)
        failed = total - passed
        risks: Dict[str, int] = {}
        for result in self.results:
            risk = result.risk
            risks[risk] = risks.get(risk, 0) + (0 if result.success else 1)
        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "risk_breakdown": risks,
        }

    @staticmethod
    def merge_reports(reports: List["ReportGenerator"]) -> "ReportGenerator":
        combined_results: List[ScanResult] = []
        for report in reports:
            combined_results.extend(report.results)
        return ReportGenerator(combined_results)

"""Fallback stub for the requests library used in tests when dependency is missing."""

from __future__ import annotations

from typing import Any


class RequestException(Exception):
    """Raised when an HTTP request fails."""


class Session:  # pragma: no cover - simple runtime guard
    """Minimal stub mimicking :class:`requests.Session`."""

    def request(self, method: str, url: str, **kwargs: Any):
        raise RuntimeError(
            "The 'requests' package is required to perform HTTP operations. "
            "Install it with 'pip install requests'."
        )

"""Compat layer to import `requests` with a fallback stub."""

from __future__ import annotations

try:  # pragma: no cover - import guard
    import requests as _requests
except ModuleNotFoundError:  # pragma: no cover - fallback when dependency missing
    from . import _requests_stub as _requests

requests = _requests

__all__ = ["requests"]

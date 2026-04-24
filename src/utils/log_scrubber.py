"""
Logging filter that scrubs obvious secrets and targets out of log records.

Applied at import time by ``server.py``. Also used by worker / engines so that
CLI targets (IP addresses, hostnames) do not make it into log aggregation.
"""

from __future__ import annotations

import logging
import re

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_AUTH_RE = re.compile(r"(?i)(authorization:\s*bearer\s+)[a-z0-9._-]+", re.IGNORECASE)
_API_KEY_RE = re.compile(r"(?i)(api[_-]?key[\"'\s:=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE)


class SensitiveDataFilter(logging.Filter):
    """Strip IPs, bearer tokens and api keys from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True

        scrubbed = _IP_RE.sub("[REDACTED_IP]", message)
        scrubbed = _AUTH_RE.sub(r"\1[REDACTED_TOKEN]", scrubbed)
        scrubbed = _API_KEY_RE.sub(r"\1[REDACTED_KEY]", scrubbed)

        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


def install_scrubber(logger: logging.Logger | None = None) -> None:
    """Attach :class:`SensitiveDataFilter` to ``logger`` (root by default)."""
    target = logger if logger is not None else logging.getLogger()
    already_installed = any(isinstance(f, SensitiveDataFilter) for f in target.filters)
    if not already_installed:
        target.addFilter(SensitiveDataFilter())

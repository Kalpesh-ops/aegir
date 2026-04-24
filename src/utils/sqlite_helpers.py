"""
Small helper around :func:`sqlite3.connect` that enables WAL mode.

The worker thread, the API request threads, and (in the Electron build) a
sidecar packager may all touch the same databases concurrently. SQLite's
default rollback-journal mode serialises writes and occasionally surfaces
``database is locked`` under contention; WAL lets readers and writers coexist
and makes the code far more forgiving of bursty traffic.

Usage::

    from src.utils.sqlite_helpers import connect

    conn = connect(DB_PATH)

The PRAGMAs are idempotent and cheap — issuing them on every connection keeps
the call sites consistent with the previous ``sqlite3.connect`` pattern while
still guaranteeing the right mode regardless of who opened the DB first.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def connect(db_path: PathLike, *, timeout: float = 30.0, **kwargs) -> sqlite3.Connection:
    """
    Return a :class:`sqlite3.Connection` with WAL + a sane busy timeout.

    ``timeout`` is passed straight through; it governs how long SQLite waits
    for a contended lock before raising. ``kwargs`` is forwarded to
    :func:`sqlite3.connect` for callers who need e.g. ``detect_types``.
    """
    conn = sqlite3.connect(str(db_path), timeout=timeout, **kwargs)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.DatabaseError as exc:  # pragma: no cover - defensive
        # A corrupted DB or an exotic filesystem (e.g. a memfd) can refuse WAL;
        # we log and keep going rather than crash the backend.
        logger.warning("Could not set WAL pragmas on %s: %s", db_path, exc)
    return conn

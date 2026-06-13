"""
Shared constants used across the API layer and the background worker.

Keeping the scan-mode and job-status vocabularies in one place prevents the
string literals from drifting between ``server.py`` (request validation),
``src/queue/job_manager.py`` (persistence) and ``src/queue/worker.py``
(pipeline dispatch).
"""

from enum import Enum


class ScanMode(str, Enum):
    """Scan profiles accepted by ``POST /api/scan``."""

    FAST = "fast"
    DEEP = "deep"
    PEN_TEST = "pen_test"


class JobStatus(str, Enum):
    """Lifecycle states of a queued scan job in SQLite."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"

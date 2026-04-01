import os
import json
import uuid
import sqlite3
import logging
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

_JOBS_DB = os.path.join(os.path.dirname(__file__), "..", "..", "data", "jobs.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_JOBS_DB), exist_ok=True)
    conn = sqlite3.connect(_JOBS_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_jobs ("
        "job_id TEXT PRIMARY KEY,"
        "user_id TEXT,"
        "target TEXT,"
        "scan_mode TEXT DEFAULT 'fast',"
        "status TEXT,"
        "created_at TEXT,"
        "result_json TEXT,"
        "error_message TEXT"
        ")"
    )

    # Backward-compatible schema migration for existing databases.
    try:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(scan_jobs)").fetchall()
        }
        if "scan_mode" not in columns:
            conn.execute(
                "ALTER TABLE scan_jobs ADD COLUMN scan_mode TEXT DEFAULT 'fast'"
            )
            conn.commit()
    except Exception as e:
        logging.error(f"Failed ensuring scan_mode column exists: {e}")
        raise

    return conn


def create_job(user_id: str, target: str, scan_mode: str = "fast") -> str:
    """
    Insert a new scan job with status "queued".

    Args:
        user_id: Identifier for the requesting user.
        target: IP address or hostname to scan.
        scan_mode: Requested scan profile (fast, deep, pen_test).

    Returns:
        The generated job_id (UUID string).
    """
    job_id = str(uuid.uuid4())
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO scan_jobs (job_id, user_id, target, scan_mode, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                job_id,
                user_id,
                target,
                scan_mode,
                "queued",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        logging.info(
            f"Created job {job_id} for user {user_id}, target {target}, mode {scan_mode}"
        )
    except Exception as e:
        logging.error(f"Failed to create job: {e}")
        raise
    return job_id


def get_next_job() -> dict | None:
    """
    Fetch the oldest queued job.

    Returns:
        Dict with all columns on success, or None if the queue is empty.
    """
    try:
        conn = _get_conn()
        cursor = conn.execute(
            "SELECT job_id, user_id, target, scan_mode, status, created_at "
            "FROM scan_jobs WHERE status = ? ORDER BY created_at ASC LIMIT 1",
            ("queued",),
        )
        row = cursor.fetchone()
        conn.close()
        if row is None:
            return None
        return {
            "job_id": row[0],
            "user_id": row[1],
            "target": row[2],
            "scan_mode": row[3] or "fast",
            "status": row[4],
            "created_at": row[5],
        }
    except Exception as e:
        logging.error(f"Failed to get next job: {e}")
        return None


def mark_running(job_id: str) -> None:
    """Update a job's status to "running"."""
    try:
        conn = _get_conn()
        conn.execute(
            "UPDATE scan_jobs SET status = ? WHERE job_id = ?",
            ("running", job_id),
        )
        conn.commit()
        conn.close()
        logging.info(f"Job {job_id} marked as running")
    except Exception as e:
        logging.error(f"Failed to mark job {job_id} running: {e}")
        raise


def mark_complete(job_id: str, result: dict) -> None:
    """
    Update a job's status to "complete" and store the result JSON.

    Args:
        job_id: The job to complete.
        result: Scan result dict to serialize and store.
    """
    try:
        conn = _get_conn()
        conn.execute(
            "UPDATE scan_jobs SET status = ?, result_json = ? WHERE job_id = ?",
            ("complete", json.dumps(result), job_id),
        )
        conn.commit()
        conn.close()
        logging.info(f"Job {job_id} marked complete")
    except Exception as e:
        logging.error(f"Failed to mark job {job_id} complete: {e}")
        raise


def mark_failed(job_id: str, error: str) -> None:
    """
    Update a job's status to "failed" and store the error message.

    Args:
        job_id: The job that failed.
        error: Error description string.
    """
    try:
        conn = _get_conn()
        conn.execute(
            "UPDATE scan_jobs SET status = ?, error_message = ? WHERE job_id = ?",
            ("failed", error, job_id),
        )
        conn.commit()
        conn.close()
        logging.error(f"Job {job_id} marked failed: {error}")
    except Exception as e:
        logging.error(f"Failed to mark job {job_id} failed: {e}")
        raise


def get_job_status(job_id: str) -> dict:
    """
    Retrieve the current status and result/error for a job.

    Args:
        job_id: The job to look up.

    Returns:
        Dict with job_id, status, result_json (parsed or None), and error_message
        (or None). Returns an empty dict if the job is not found.
    """
    try:
        conn = _get_conn()
        cursor = conn.execute(
            "SELECT job_id, user_id, scan_mode, status, result_json, error_message "
            "FROM scan_jobs WHERE job_id = ?",
            (job_id,),
        )
        row = cursor.fetchone()
        conn.close()
        if row is None:
            return {}
        result_json = None
        if row[4]:
            try:
                result_json = json.loads(row[4])
            except Exception:
                result_json = row[4]
        return {
            "job_id": row[0],
            "user_id": row[1],
            "scan_mode": row[2] or "fast",
            "status": row[3],
            "result_json": result_json,
            "error_message": row[5],
        }
    except Exception as e:
        logging.error(f"Failed to get job status for {job_id}: {e}")
        return {}

def clear_user_jobs(user_id: str) -> None:
    """
    Deletes all scan jobs for a specific user from the local SQLite database.
    """
    try:
        conn = _get_conn()
        conn.execute(
            "DELETE FROM scan_jobs WHERE user_id = ?",
            (user_id,)
        )
        conn.commit()
        conn.close()
        logging.info(f"Cleared local job history for user {user_id}")
    except Exception as e:
        logging.error(f"Failed to clear local jobs for user {user_id}: {e}")
        raise
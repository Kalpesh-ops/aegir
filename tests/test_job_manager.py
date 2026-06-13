"""Job-queue lifecycle against a real (temporary) SQLite database."""

from __future__ import annotations

import pytest

from src.constants import JobStatus, ScanMode
from src.queue import job_manager


@pytest.fixture
def temp_jobs_db(tmp_path, monkeypatch):
    """Point job_manager at a throwaway jobs.db for each test."""
    db = tmp_path / "jobs.db"
    monkeypatch.setattr(job_manager, "_JOBS_DB", str(db))
    return db


def test_create_then_get_next_returns_queued_job(temp_jobs_db):
    job_id = job_manager.create_job("user-1", "192.168.1.5", ScanMode.DEEP.value)

    nxt = job_manager.get_next_job()
    assert nxt is not None
    assert nxt["job_id"] == job_id
    assert nxt["target"] == "192.168.1.5"
    assert nxt["scan_mode"] == ScanMode.DEEP.value
    assert nxt["status"] == JobStatus.QUEUED.value


def test_get_next_job_is_fifo(temp_jobs_db):
    first = job_manager.create_job("u", "10.0.0.1")
    job_manager.create_job("u", "10.0.0.2")
    assert job_manager.get_next_job()["job_id"] == first


def test_get_next_job_empty_queue_returns_none(temp_jobs_db):
    assert job_manager.get_next_job() is None


def test_mark_running_removes_job_from_queue(temp_jobs_db):
    job_id = job_manager.create_job("u", "10.0.0.1")
    job_manager.mark_running(job_id)

    assert job_manager.get_next_job() is None
    assert job_manager.get_job_status(job_id)["status"] == JobStatus.RUNNING.value


def test_mark_complete_stores_result(temp_jobs_db):
    job_id = job_manager.create_job("u", "10.0.0.1")
    job_manager.mark_complete(job_id, {"ports": [22, 80], "ai_summary": "ok"})

    status = job_manager.get_job_status(job_id)
    assert status["status"] == JobStatus.COMPLETE.value
    assert status["result_json"]["ports"] == [22, 80]
    assert status["error_message"] is None


def test_mark_failed_stores_error(temp_jobs_db):
    job_id = job_manager.create_job("u", "10.0.0.1")
    job_manager.mark_failed(job_id, "scan blew up")

    status = job_manager.get_job_status(job_id)
    assert status["status"] == JobStatus.FAILED.value
    assert status["error_message"] == "scan blew up"


def test_get_job_status_unknown_id_returns_empty(temp_jobs_db):
    assert job_manager.get_job_status("nope") == {}


def test_get_job_status_carries_user_id(temp_jobs_db):
    job_id = job_manager.create_job("owner-42", "10.0.0.1")
    assert job_manager.get_job_status(job_id)["user_id"] == "owner-42"


def test_clear_user_jobs_only_removes_that_user(temp_jobs_db):
    mine = job_manager.create_job("me", "10.0.0.1")
    theirs = job_manager.create_job("you", "10.0.0.2")

    job_manager.clear_user_jobs("me")

    assert job_manager.get_job_status(mine) == {}
    assert job_manager.get_job_status(theirs)["user_id"] == "you"

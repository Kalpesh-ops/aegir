"""End-to-end endpoint tests against the real server.app.

Auth is replaced via FastAPI dependency overrides; the database/AI layers are
monkeypatched so no network or Supabase project is required. Routing, the auth
gate, the ownership check, validation, and rate limiting are all exercised for
real.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

import server
from src.auth.middleware import get_current_user

USER = "user-123"


@pytest.fixture(autouse=True)
def _reset_rate_buckets():
    """Rate-limit state is module-global; clear it around every test."""
    server._rate_buckets.clear()
    yield
    server._rate_buckets.clear()


@pytest.fixture
def client_authed():
    server.app.dependency_overrides[get_current_user] = lambda: USER
    try:
        yield TestClient(server.app, base_url="http://localhost")
    finally:
        server.app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def client_anon():
    """No override → the real JWT dependency runs and rejects missing tokens."""
    return TestClient(server.app, base_url="http://localhost", raise_server_exceptions=False)


# --- Auth gate ---------------------------------------------------------------
def test_scan_requires_auth(client_anon):
    resp = client_anon.post("/api/scan", json={"target": "192.168.1.1"})
    assert resp.status_code == 401


def test_scans_list_requires_auth(client_anon):
    assert client_anon.get("/api/scans").status_code == 401


def test_health_is_public(client_anon):
    resp = client_anon.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}


# --- Scan queue --------------------------------------------------------------
def test_scan_happy_path_queues_job(client_authed, monkeypatch):
    monkeypatch.setattr(server, "create_job", lambda uid, target, mode: "job-abc")

    resp = client_authed.post("/api/scan", json={"target": "192.168.1.10", "scan_mode": "fast"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == "job-abc"
    assert body["status"] == "queued"


def test_scan_rejects_public_target(client_authed):
    resp = client_authed.post("/api/scan", json={"target": "8.8.8.8"})
    assert resp.status_code == 400


def test_scan_rejects_invalid_mode(client_authed):
    resp = client_authed.post("/api/scan", json={"target": "192.168.1.1", "scan_mode": "nuke"})
    assert resp.status_code == 422  # pydantic enum validation


def test_scan_rate_limit_returns_429(client_authed, monkeypatch):
    monkeypatch.setattr(server, "create_job", lambda uid, target, mode: "job-x")

    # Limit is 5 scans/hour. The 6th must be throttled.
    for _ in range(5):
        ok = client_authed.post("/api/scan", json={"target": "192.168.1.1"})
        assert ok.status_code == 200
    throttled = client_authed.post("/api/scan", json={"target": "192.168.1.1"})
    assert throttled.status_code == 429


# --- Ownership check on /api/scan/{id} ---------------------------------------
def test_scan_status_blocks_other_users_job(client_authed, monkeypatch):
    monkeypatch.setattr(
        server, "get_job_status",
        lambda sid: {"job_id": sid, "user_id": "someone-else", "status": "complete"},
    )
    resp = client_authed.get("/api/scan/job-1")
    assert resp.status_code == 403


def test_scan_status_returns_own_job(client_authed, monkeypatch):
    monkeypatch.setattr(
        server, "get_job_status",
        lambda sid: {"job_id": sid, "user_id": USER, "status": "complete"},
    )
    resp = client_authed.get("/api/scan/job-1")
    assert resp.status_code == 200
    assert resp.json()["user_id"] == USER


def test_scan_status_unknown_job_404(client_authed, monkeypatch):
    monkeypatch.setattr(server, "get_job_status", lambda sid: {})
    assert client_authed.get("/api/scan/ghost").status_code == 404


# --- Scans list + delete -----------------------------------------------------
def test_list_scans_returns_user_rows(client_authed, monkeypatch):
    monkeypatch.setattr(server, "get_user_scans", lambda uid: [{"id": 1, "user_id": uid}])
    resp = client_authed.get("/api/scans")
    assert resp.status_code == 200
    assert resp.json() == [{"id": 1, "user_id": USER}]


def test_delete_scans_clears_history(client_authed, monkeypatch):
    monkeypatch.setattr(server, "supabase_delete_user_scans", lambda uid: 3)
    monkeypatch.setattr(server, "clear_user_jobs", lambda uid: None)
    resp = client_authed.delete("/api/scans")
    assert resp.status_code == 200
    assert resp.json()["deleted_supabase_rows"] == 3

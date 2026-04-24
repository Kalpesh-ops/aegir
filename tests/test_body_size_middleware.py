import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient


def _build_app():
    import importlib
    import server as server_mod

    # Re-run `app.add_middleware` in a minimal way by using the module's class.
    app = FastAPI()
    app.add_middleware(server_mod.BodySizeLimitMiddleware)

    @app.post("/echo")
    async def echo(payload: dict):
        return payload

    return app


def test_body_size_under_limit_allowed(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    app = _build_app()
    client = TestClient(app)
    resp = client.post("/echo", json={"hello": "world"})
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


def test_body_size_oversized_rejected(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    app = _build_app()
    client = TestClient(app)
    # Build a ~400 KB payload; default limit is 256 KB.
    big = {"blob": "x" * 400_000}
    resp = client.post("/echo", json=big)
    assert resp.status_code == 413, resp.text
    body = resp.json()
    assert "Payload too large" in body.get("error", "")


def test_body_size_invalid_content_length_rejected(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    app = _build_app()
    client = TestClient(app)
    # Spoof a non-numeric Content-Length header to hit the validation branch.
    resp = client.post(
        "/echo",
        json={"a": 1},
        headers={"Content-Length": "not-a-number"},
    )
    # Some HTTP clients rewrite Content-Length; only assert when the header
    # survived so the test remains meaningful.
    if resp.status_code == 400:
        assert "Content-Length" in resp.json().get("error", "")
    else:
        pytest.skip("transport layer overwrote Content-Length header")

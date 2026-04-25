"""Detection-layer behaviour (cache, version-regex extraction, fallback)."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from src.dependencies import detector


@pytest.fixture(autouse=True)
def _clear_cache():
    detector.invalidate_cache()
    yield
    detector.invalidate_cache()


def test_detect_via_argv_extracts_version(monkeypatch):
    def fake_which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    def fake_run(argv, **kwargs):
        return SimpleNamespace(stdout="Nmap version 7.95 ( https://nmap.org )\n", stderr="", returncode=0)

    monkeypatch.setattr(detector.shutil, "which", fake_which)
    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    result = detector.detect_one("nmap")
    assert result.installed is True
    assert result.version == "7.95"


def test_detect_returns_not_installed_when_binary_missing(monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda _: None)

    result = detector.detect_one("nmap")
    assert result.installed is False
    assert result.version is None


def test_detect_handles_subprocess_timeout(monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda _: "/usr/bin/nmap")

    def boom(*_, **__):
        raise subprocess.TimeoutExpired(cmd=["nmap"], timeout=1)

    monkeypatch.setattr(detector.subprocess, "run", boom)
    result = detector.detect_one("nmap")
    assert result.installed is False
    assert result.error is not None


def test_detect_caches_results(monkeypatch):
    calls = {"n": 0}

    def fake_which(_):
        return "/usr/bin/nmap"

    def fake_run(argv, **kwargs):
        calls["n"] += 1
        return SimpleNamespace(stdout="Nmap version 7.95\n", stderr="", returncode=0)

    monkeypatch.setattr(detector.shutil, "which", fake_which)
    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    detector.detect_one("nmap")
    detector.detect_one("nmap")
    assert calls["n"] == 1  # second call hit the cache


def test_public_status_merges_registry_and_detection(monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda _: None)

    rows = detector.public_status()
    by_id = {r["id"]: r for r in rows}
    assert "nmap" in by_id
    assert by_id["nmap"]["installed"] is False
    assert by_id["nmap"]["display_name"] == "Nmap"
    assert "license_url" in by_id["nmap"]

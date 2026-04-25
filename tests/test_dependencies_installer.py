"""License acceptance + queue-install gating + simulated install runs."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.dependencies import detector, installer, registry


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSEC_DATA_DIR", str(tmp_path))
    detector.invalidate_cache()
    installer._jobs.clear()  # noqa: SLF001 — test isolation.
    yield


def test_license_record_round_trip(tmp_path):
    assert installer.has_license_acceptance("nmap") is False
    installer.record_license_acceptance(
        "nmap", "https://nmap.org/npsl/npsl-license.html", user_id="u1"
    )
    assert installer.has_license_acceptance("nmap") is True

    records = json.loads((tmp_path / "dep_licenses.json").read_text())
    assert len(records) == 1
    assert records[0]["dep_id"] == "nmap"
    assert records[0]["user_id"] == "u1"
    assert records[0]["accepted_at"].endswith("+00:00")


def test_queue_install_blocks_without_license_acceptance(monkeypatch):
    """Installer must refuse to start until the upstream license is acknowledged."""
    spec = registry.get_platform_spec("nmap")
    assert spec is not None and spec.get("install_method") != "not_applicable"

    with pytest.raises(PermissionError):
        installer.queue_install("nmap", user_id="u1")


def test_queue_install_rejects_unknown_dep():
    with pytest.raises(ValueError):
        installer.queue_install("not-a-real-dep")


def test_run_official_installer_with_sha_mismatch(monkeypatch, tmp_path):
    """If the downloaded blob's SHA256 doesn't match the registry pin, fail loudly."""
    job = installer.InstallJob(id="t1", dep_id="nmap")
    fake_spec = {
        "install_method": "official_installer",
        "url": "https://example.invalid/installer.exe",
        "sha256": "0" * 64,
        "args": [],
        "elevate": False,
    }

    def fake_download(j, url, dest):
        dest.write_bytes(b"not-the-real-bytes")
        j.bytes_downloaded = 20
        j.bytes_total = 20

    monkeypatch.setattr(installer, "_download", fake_download)

    with pytest.raises(RuntimeError, match="SHA256 mismatch"):
        installer._run_official_installer(job, fake_spec)


def test_run_shell_install_invokes_command(monkeypatch):
    job = installer.InstallJob(id="t2", dep_id="nmap")
    captured = {}

    def fake_run(cmd, capture_output, text, timeout, check):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)

    installer._run_shell_install(job, {"command": ["echo", "hi"], "elevate": False})
    assert captured["cmd"] == ["echo", "hi"]
    assert job.status == "installing"


def test_install_job_succeeds_end_to_end(monkeypatch):
    """Happy-path: shell install runs cleanly + detector sees the binary post-install."""
    detector.invalidate_cache()
    installer.record_license_acceptance(
        "nmap", "https://nmap.org/npsl/npsl-license.html", user_id="u1"
    )

    monkeypatch.setattr(
        registry,
        "get_platform_spec",
        lambda dep_id, platform=None: {
            "install_method": "shell",
            "command": ["echo", "installed"],
            "elevate": False,
        }
        if dep_id == "nmap"
        else None,
    )
    monkeypatch.setattr(
        detector,
        "detect_one",
        lambda dep_id: detector.DetectionResult(
            id=dep_id, installed=True, version="7.95"
        ),
    )

    job = installer.queue_install("nmap", user_id="u1")
    # Worker thread is daemon; poll briefly.
    import time
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        latest = installer.status(job.id)
        if latest and latest.status in {"succeeded", "failed", "cancelled"}:
            break
        time.sleep(0.05)

    final = installer.status(job.id)
    assert final is not None
    assert final.status == "succeeded", final.error

"""Downloads + verifies + executes upstream installers on the user's machine.

Job state is held in-memory (process-local). The wizard polls ``status()`` to
render progress; the API surface in ``server.py`` translates that to JSON.

License acceptance is required before a job is queued: the user must
explicitly tick the upstream-license box for every dep whose
``license_url`` is non-empty. The acceptance is persisted to
``data/dep_licenses.json`` with a UTC timestamp and the URL the user saw,
so we have an audit trail if the upstream vendor (especially Insecure.com
re Nmap/Npcap) ever asks how end-users came to install their software via
this app.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Literal

import requests

from . import detector, registry

logger = logging.getLogger(__name__)

JobStatus = Literal[
    "queued", "downloading", "verifying", "installing", "succeeded", "failed", "cancelled"
]

# Where we cache downloaded installers + persist license acceptance.
def _data_dir() -> Path:
    base = Path(os.environ.get("NETSEC_DATA_DIR", "data"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def _installer_cache_dir() -> Path:
    d = _data_dir() / "installers"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _license_log_path() -> Path:
    return _data_dir() / "dep_licenses.json"


_DOWNLOAD_TIMEOUT_S = 300
_INSTALL_TIMEOUT_S = 600
_CHUNK_SIZE = 65_536


@dataclass
class InstallJob:
    id: str
    dep_id: str
    status: JobStatus = "queued"
    bytes_downloaded: int = 0
    bytes_total: int | None = None
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    error: str | None = None
    log: list[str] = field(default_factory=list)
    cancel_requested: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "dep_id": self.dep_id,
            "status": self.status,
            "bytes_downloaded": self.bytes_downloaded,
            "bytes_total": self.bytes_total,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "log": list(self.log),
        }


_jobs: dict[str, InstallJob] = {}
_jobs_lock = threading.Lock()


# ── License acknowledgement ───────────────────────────────────────────────


def record_license_acceptance(dep_id: str, license_url: str, *, user_id: str | None = None) -> None:
    """Append a tamper-evident-ish JSON record of the user's license acceptance."""
    payload = {
        "dep_id": dep_id,
        "license_url": license_url,
        "user_id": user_id,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    }
    log_path = _license_log_path()
    existing: list[dict[str, object]] = []
    if log_path.exists():
        try:
            existing = json.loads(log_path.read_text(encoding="utf-8")) or []
        except json.JSONDecodeError:
            logger.warning("Corrupt dep_licenses.json; rotating to .bak.")
            log_path.rename(log_path.with_suffix(".json.bak"))
    existing.append(payload)
    log_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def has_license_acceptance(dep_id: str) -> bool:
    log_path = _license_log_path()
    if not log_path.exists():
        return False
    try:
        existing = json.loads(log_path.read_text(encoding="utf-8")) or []
    except json.JSONDecodeError:
        return False
    return any(rec.get("dep_id") == dep_id for rec in existing)


# ── Job lifecycle ─────────────────────────────────────────────────────────


def queue_install(dep_id: str, *, user_id: str | None = None) -> InstallJob:
    spec = registry.get_platform_spec(dep_id)
    if not spec:
        raise ValueError(f"Unknown dependency: {dep_id!r}")

    method = spec.get("install_method")
    if method == "not_applicable":
        raise ValueError(f"{dep_id} is not applicable on this platform.")
    if method == "manual":
        raise ValueError(f"{dep_id} has no automated install path; install manually.")

    license_url = registry.get_dependency(dep_id) or {}
    license_url = license_url.get("license_url") if isinstance(license_url, dict) else None
    if license_url and not has_license_acceptance(dep_id):
        raise PermissionError(
            f"Upstream license for {dep_id} has not been accepted yet."
        )

    job = InstallJob(id=uuid.uuid4().hex, dep_id=dep_id)
    with _jobs_lock:
        _jobs[job.id] = job

    thread = threading.Thread(target=_run_job, args=(job.id,), daemon=True)
    thread.start()
    return job


def cancel(job_id: str) -> bool:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return False
    if job.status in {"succeeded", "failed", "cancelled"}:
        return False
    job.cancel_requested = True
    return True


def status(job_id: str) -> InstallJob | None:
    with _jobs_lock:
        return _jobs.get(job_id)


def all_statuses() -> list[dict[str, object]]:
    with _jobs_lock:
        return [j.to_dict() for j in _jobs.values()]


# ── Job runner ────────────────────────────────────────────────────────────


def _run_job(job_id: str) -> None:
    job = _jobs[job_id]
    try:
        spec = registry.get_platform_spec(job.dep_id)
        if not spec:
            raise RuntimeError(f"No platform spec for {job.dep_id}")

        method = spec["install_method"]
        if method == "official_installer":
            _run_official_installer(job, spec)
        elif method == "shell":
            _run_shell_install(job, spec)
        else:
            raise RuntimeError(f"Unsupported install method: {method}")

        detector.invalidate_cache(job.dep_id)
        result = detector.detect_one(job.dep_id)
        if result.installed:
            _set(job, status="succeeded", log=f"Verified install: {job.dep_id} {result.version or ''}")
        else:
            _set(
                job,
                status="failed",
                error="Installer ran but the dependency is still not detected. "
                "Try a manual install from the vendor's site.",
            )
    except Exception as exc:  # noqa: BLE001 — top-level worker boundary.
        logger.exception("Install job %s failed", job_id)
        _set(job, status="failed", error=str(exc))


def _run_official_installer(job: InstallJob, spec: dict) -> None:
    url = spec["url"]
    expected_sha = spec.get("sha256")
    args = list(spec.get("args") or [])
    elevate = bool(spec.get("elevate"))

    cached = _installer_cache_dir() / _filename_from_url(url)
    if cached.exists() and expected_sha and _sha256(cached) == expected_sha:
        _set(job, log=f"Using cached installer: {cached.name}")
    else:
        _download(job, url, cached)

    if expected_sha:
        _set(job, status="verifying")
        actual = _sha256(cached)
        if actual != expected_sha.lower():
            cached.unlink(missing_ok=True)
            raise RuntimeError(
                f"SHA256 mismatch for {cached.name}: expected {expected_sha}, got {actual}"
            )
        _set(job, log=f"SHA256 verified: {actual[:16]}…")
    else:
        _set(job, log="WARNING: no SHA256 pin for this installer; trusting TLS only.")

    _set(job, status="installing", log=f"Spawning installer: {cached.name} {' '.join(args)}")
    cmd = [str(cached), *args]
    _spawn_installer(cmd, elevate=elevate, timeout=_INSTALL_TIMEOUT_S, job=job)


def _run_shell_install(job: InstallJob, spec: dict) -> None:
    cmd: list[str] = list(spec["command"])
    elevate = bool(spec.get("elevate"))
    _set(job, status="installing", log=f"Spawning: {' '.join(cmd)}")
    _spawn_installer(cmd, elevate=elevate, timeout=_INSTALL_TIMEOUT_S, job=job)


def _spawn_installer(cmd: list[str], *, elevate: bool, timeout: int, job: InstallJob) -> None:
    # On POSIX shells we already prefix sudo in the registry where needed.
    # On Windows the user has been UAC-prompted at app launch (per
    # `requestedExecutionLevel: requireAdministrator`) so the installer
    # inherits admin already.
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Installer timed out after {timeout}s") from exc

    if proc.returncode != 0:
        snippet = (proc.stderr or proc.stdout or "").splitlines()
        tail = " | ".join(snippet[-5:]) if snippet else ""
        raise RuntimeError(
            f"Installer exited with code {proc.returncode}: {tail}"
        )

    if proc.stdout:
        _set(job, log=f"stdout: {proc.stdout.strip()[:400]}")


def _download(job: InstallJob, url: str, dest: Path) -> None:
    _set(job, status="downloading", log=f"Downloading {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    sha = hashlib.sha256()
    with requests.get(url, stream=True, timeout=_DOWNLOAD_TIMEOUT_S, allow_redirects=True) as resp:
        resp.raise_for_status()
        total = resp.headers.get("Content-Length")
        if total is not None:
            try:
                job.bytes_total = int(total)
            except ValueError:
                pass
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=_CHUNK_SIZE):
                if job.cancel_requested:
                    fh.close()
                    tmp.unlink(missing_ok=True)
                    _set(job, status="cancelled", log="Cancelled by user.")
                    raise RuntimeError("cancelled")
                if not chunk:
                    continue
                fh.write(chunk)
                sha.update(chunk)
                job.bytes_downloaded += len(chunk)
                job.updated_at = time.time()

    tmp.replace(dest)
    _set(job, log=f"Downloaded {dest.name} ({job.bytes_downloaded} bytes, sha256 {sha.hexdigest()[:16]}…)")


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _filename_from_url(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1]
    return name or "installer.bin"


def _set(job: InstallJob, *, status: JobStatus | None = None, log: str | None = None, error: str | None = None) -> None:
    if status is not None:
        job.status = status
        if status in {"succeeded", "failed", "cancelled"}:
            job.completed_at = time.time()
    if error is not None:
        job.error = error
    if log is not None:
        job.log.append(log)
        logger.info("[install %s] %s", job.id, log)
    job.updated_at = time.time()

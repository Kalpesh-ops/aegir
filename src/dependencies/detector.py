"""Probes the live system to see which scanner dependencies are installed.

The detector runs sub-processes that should be safe to spawn unconditionally:

* ``nmap --version`` — exits with the version string on stdout.
* ``tshark --version`` — same.
* On Windows we additionally consult the ``HKLM\\SOFTWARE\\Npcap`` registry
  hive because Npcap is a kernel driver, not something on PATH.

Detection results are cached for ``CACHE_TTL_S`` seconds to avoid spawning
processes on every wizard re-render.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Mapping

from . import registry

logger = logging.getLogger(__name__)

CACHE_TTL_S = 5
_PROBE_TIMEOUT_S = 8


@dataclass(frozen=True)
class DetectionResult:
    id: str
    installed: bool
    version: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "installed": self.installed,
            "version": self.version,
            "error": self.error,
        }


_cache: dict[str, tuple[float, DetectionResult]] = {}


def detect_one(dep_id: str) -> DetectionResult:
    spec = registry.get_platform_spec(dep_id)
    if not spec or spec.get("install_method") == "not_applicable":
        return DetectionResult(id=dep_id, installed=False, version=None, error="not_applicable")

    cached = _cache.get(dep_id)
    if cached and (time.monotonic() - cached[0]) < CACHE_TTL_S:
        return cached[1]

    detect = spec.get("detect")
    if detect == "_win_npcap_registry":
        result = _detect_npcap_windows(dep_id)
    elif isinstance(detect, list):
        result = _detect_via_argv(dep_id, detect, spec.get("version_re"))
    else:
        result = DetectionResult(id=dep_id, installed=False, version=None, error="no_detector")

    _cache[dep_id] = (time.monotonic(), result)
    return result


def detect_all() -> list[DetectionResult]:
    return [detect_one(d["id"]) for d in registry.list_dependencies()]


def invalidate_cache(dep_id: str | None = None) -> None:
    if dep_id is None:
        _cache.clear()
    else:
        _cache.pop(dep_id, None)


def _detect_via_argv(
    dep_id: str,
    argv: list[str],
    version_re: str | None,
) -> DetectionResult:
    binary = argv[0]
    if shutil.which(binary) is None:
        return DetectionResult(id=dep_id, installed=False, version=None)

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_S,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Probe failed for %s: %s", dep_id, exc)
        return DetectionResult(id=dep_id, installed=False, version=None, error=str(exc))

    haystack = (proc.stdout or "") + "\n" + (proc.stderr or "")
    version: str | None = None
    if version_re:
        match = re.search(version_re, haystack)
        if match:
            version = match.group(1)

    return DetectionResult(id=dep_id, installed=True, version=version)


def _detect_npcap_windows(dep_id: str) -> DetectionResult:
    """Read HKLM\\SOFTWARE\\Npcap to confirm the driver is installed."""
    if sys.platform != "win32":
        return DetectionResult(id=dep_id, installed=False, version=None, error="not_applicable")

    try:
        import winreg  # noqa: PLC0415 — stdlib but Windows-only.
    except ImportError:
        return DetectionResult(id=dep_id, installed=False, version=None, error="winreg_unavailable")

    for hive, path in (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
    ):
        try:
            with winreg.OpenKey(hive, path) as key:
                version, _ = winreg.QueryValueEx(key, "Version")
                return DetectionResult(id=dep_id, installed=True, version=str(version))
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.debug("Npcap registry read failed: %s", exc)
            continue

    return DetectionResult(id=dep_id, installed=False, version=None)


def public_status() -> list[Mapping[str, object]]:
    """Combined registry spec + live detection — ready for the API to return."""
    out: list[dict[str, object]] = []
    detection_by_id = {r.id: r for r in detect_all()}
    for dep in registry.list_dependencies():
        result = detection_by_id.get(dep["id"])
        out.append(
            {
                **dep,
                "installed": bool(result and result.installed),
                "version": result.version if result else None,
                "detection_error": result.error if result else None,
            }
        )
    return out

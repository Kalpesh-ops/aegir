"""Declarative registry of native dependencies the scanner can drive.

For each dependency × platform we capture:

* ``detect``         — argv to spawn so we can probe the binary on PATH.
* ``version_re``     — optional regex run against ``stdout``+``stderr`` to
                       extract a human-readable version string.
* ``install_method`` — one of: ``official_installer``, ``shell``,
                       ``manual``. ``manual`` means we have no automated
                       path; the wizard surfaces the upstream URL only.
* ``url``            — official download URL (only for
                       ``official_installer``). The bytes are downloaded
                       on the user's machine at install time; this app
                       never redistributes.
* ``sha256``         — known-good SHA256 of the downloaded file. May be
                       ``None`` for installers we can't pin (rolling
                       releases). The wizard surfaces a clear warning
                       when ``sha256`` is missing.
* ``size_mb``        — approximate download size for the UX.
* ``args``           — argv passed to the installer (silent flags etc).
* ``elevate``        — whether the installer expects to be UAC-elevated
                       on Windows / sudo'd on POSIX.
* ``command``        — for ``shell`` method, the shell command we spawn
                       on the user's behalf (e.g. ``brew install nmap``).

Bundling Nmap or Npcap binaries in the application installer would
require commercial redistribution licenses we don't have. The pattern
here — automate the user's installation of upstream packages — keeps us
clear of those licensing constraints.
"""

from __future__ import annotations

import sys
from typing import Any, Mapping

# Hashes are taken from the upstream signature files at the time of pinning.
# When bumping a version, fetch the new SHA256 from the vendor's signed
# digest file (e.g. https://nmap.org/dist/sigs/<ver>-setup.exe.digest.txt)
# and update both the URL and the hash atomically.
NMAP_WINDOWS_VERSION = "7.95"
NMAP_WINDOWS_URL = f"https://nmap.org/dist/nmap-{NMAP_WINDOWS_VERSION}-setup.exe"
NMAP_WINDOWS_SHA256 = (
    "c59b51d15b5965f27db4c5bbd21793ad6b492c8c751836ba8bd43829d791146e"
)

# Wireshark and Npcap publish "latest" redirects but rotate hashes silently.
# We keep the URL pinned to the latest stable build and intentionally skip
# SHA256 verification — the wizard tells the user they're trusting the
# vendor's TLS endpoint instead of our pin. A follow-up PR can swap to
# specific pinned versions once we have an automation to bump them.
WIRESHARK_WINDOWS_URL = "https://2.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe"
NPCAP_WINDOWS_URL = "https://npcap.com/dist/npcap-1.79.exe"

# Public-facing IDs. Order matters — the wizard renders them in this order.
_DEPENDENCIES: dict[str, dict[str, Any]] = {
    "nmap": {
        "id": "nmap",
        "display_name": "Nmap",
        "purpose": "Port scanning and service-version detection.",
        "required_for": ["fast", "deep", "pen"],
        "license_name": "Nmap Public Source License (NPSL)",
        "license_url": "https://nmap.org/npsl/npsl-license.html",
        "homepage": "https://nmap.org/",
        "platforms": {
            "win32": {
                "detect": ["nmap", "--version"],
                "version_re": r"Nmap version\s+(\S+)",
                "install_method": "official_installer",
                "url": NMAP_WINDOWS_URL,
                "sha256": NMAP_WINDOWS_SHA256,
                "size_mb": 27,
                "args": ["/S"],
                "elevate": True,
            },
            "darwin": {
                "detect": ["nmap", "--version"],
                "version_re": r"Nmap version\s+(\S+)",
                "install_method": "shell",
                "command": ["brew", "install", "nmap"],
                "elevate": False,
            },
            "linux": {
                "detect": ["nmap", "--version"],
                "version_re": r"Nmap version\s+(\S+)",
                "install_method": "shell",
                "command": ["sudo", "apt-get", "install", "-y", "nmap"],
                "elevate": True,
            },
        },
    },
    "tshark": {
        "id": "tshark",
        "display_name": "Wireshark / TShark",
        "purpose": "Live packet capture for deep + pen-test scans.",
        "required_for": ["deep", "pen"],
        "license_name": "GNU GPLv2",
        "license_url": "https://www.wireshark.org/about.html#license",
        "homepage": "https://www.wireshark.org/",
        "platforms": {
            "win32": {
                "detect": ["tshark", "--version"],
                "version_re": r"TShark.*?(\d+\.\d+\.\d+)",
                "install_method": "official_installer",
                "url": WIRESHARK_WINDOWS_URL,
                "sha256": None,
                "size_mb": 80,
                "args": ["/S"],
                "elevate": True,
            },
            "darwin": {
                "detect": ["tshark", "--version"],
                "version_re": r"TShark.*?(\d+\.\d+\.\d+)",
                "install_method": "shell",
                "command": ["brew", "install", "wireshark"],
                "elevate": False,
            },
            "linux": {
                "detect": ["tshark", "--version"],
                "version_re": r"TShark.*?(\d+\.\d+\.\d+)",
                "install_method": "shell",
                "command": ["sudo", "apt-get", "install", "-y", "tshark"],
                "elevate": True,
            },
        },
    },
    "npcap": {
        "id": "npcap",
        "display_name": "Npcap",
        "purpose": "Windows packet-capture driver. Required by Nmap and Scapy.",
        "required_for": ["fast", "deep", "pen"],
        "license_name": "Npcap License (free for non-commercial use)",
        "license_url": "https://npcap.com/oem/redist.html",
        "homepage": "https://npcap.com/",
        "platforms": {
            "win32": {
                "detect": "_win_npcap_registry",  # special-case in detector.py
                "install_method": "official_installer",
                "url": NPCAP_WINDOWS_URL,
                "sha256": None,
                "size_mb": 2,
                "args": ["/S"],
                "elevate": True,
            },
            # Npcap is Windows-only; on POSIX libpcap ships with the OS or
            # is pulled in by Wireshark, so we surface this dep as ``not
            # applicable`` rather than as an install task.
            "darwin": {"install_method": "not_applicable"},
            "linux": {"install_method": "not_applicable"},
        },
    },
}


def current_platform() -> str:
    """Return the registry-platform key for the live host."""
    if sys.platform.startswith("win"):
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def list_dependencies() -> list[Mapping[str, Any]]:
    """Return the user-visible specs for every dependency."""
    return [_strip_platforms(d) for d in _DEPENDENCIES.values()]


def get_dependency(dep_id: str) -> Mapping[str, Any] | None:
    spec = _DEPENDENCIES.get(dep_id)
    return _strip_platforms(spec) if spec else None


def get_platform_spec(dep_id: str, platform: str | None = None) -> Mapping[str, Any] | None:
    """Return the per-platform install spec, or ``None`` if not applicable."""
    dep = _DEPENDENCIES.get(dep_id)
    if not dep:
        return None
    plat = platform or current_platform()
    return dep["platforms"].get(plat)


def _strip_platforms(spec: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """Return the dep spec with the per-platform map flattened to the live host's entry."""
    if spec is None:
        return {}
    plat = current_platform()
    flat = {k: v for k, v in spec.items() if k != "platforms"}
    flat["platform"] = plat
    flat.update(spec["platforms"].get(plat, {"install_method": "not_applicable"}))
    return flat

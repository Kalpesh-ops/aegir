"""Sanity checks for the declarative dependency registry."""

from __future__ import annotations

from src.dependencies import registry


def test_known_deps_are_present():
    ids = {d["id"] for d in registry.list_dependencies()}
    assert {"nmap", "tshark", "npcap"}.issubset(ids)


def test_strip_platforms_flattens_for_current_host():
    spec = registry.get_dependency("nmap")
    assert spec is not None
    assert "platforms" not in spec
    assert spec["platform"] in {"win32", "darwin", "linux"}
    assert "install_method" in spec


def test_npcap_is_not_applicable_off_windows():
    if registry.current_platform() == "win32":
        return
    spec = registry.get_platform_spec("npcap")
    assert spec == {"install_method": "not_applicable"}


def test_nmap_windows_pin_is_lowercase_hex():
    spec = registry.get_platform_spec("nmap", platform="win32")
    assert spec is not None
    sha = spec["sha256"]
    assert isinstance(sha, str)
    assert len(sha) == 64
    assert sha == sha.lower()
    int(sha, 16)


def test_unknown_dependency_returns_none():
    assert registry.get_dependency("definitely-not-a-dep") is None
    assert registry.get_platform_spec("definitely-not-a-dep") is None

"""Unit tests for ``src.utils.validators.validate_target``."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from src.utils.validators import TargetValidationError, validate_target


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.1",
        "10.0.0.5",
        "172.16.0.1",
        "127.0.0.1",
        "localhost",
        "192.168.1.0/24",
        "10.0.0.0/32",
    ],
)
def test_accepts_private_targets(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "1.1.1.1",
        "169.254.169.254/16",  # AWS metadata range, /16 too broad
        "10.0.0.0/8",          # /8 too broad
        "",
        "   ",
        "-sV",
        "--datadir=/tmp",
        "ex ample.com",
        "a" * 300,
        "../etc/passwd",
        "192.168.1.1; rm -rf /",
    ],
)
def test_rejects_invalid_or_public_targets(target: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(target)


def test_public_cidr_rejected() -> None:
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.0/24")


def test_domain_with_private_resolution_accepted() -> None:
    with patch(
        "src.utils.validators.socket.getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("192.168.1.50", 0))],
    ):
        assert validate_target("router.local") == "router.local"


def test_domain_with_public_resolution_rejected() -> None:
    with patch(
        "src.utils.validators.socket.getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("8.8.8.8", 0))],
    ):
        with pytest.raises(TargetValidationError):
            validate_target("attacker.example")


def test_domain_with_mixed_resolution_rejected() -> None:
    """If ANY resolved address is public, the target must be rejected."""
    with patch(
        "src.utils.validators.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, 0, 0, "", ("192.168.1.50", 0)),
            (socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),
        ],
    ):
        with pytest.raises(TargetValidationError):
            validate_target("split-horizon.example")


def test_domain_with_dns_failure_rejected() -> None:
    with patch(
        "src.utils.validators.socket.getaddrinfo",
        side_effect=socket.gaierror("no such host"),
    ):
        with pytest.raises(TargetValidationError):
            validate_target("nosuch.invalid")

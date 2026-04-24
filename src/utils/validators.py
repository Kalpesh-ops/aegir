"""
Target validation for scan requests.

The scanner is local-first and is only allowed to probe private / loopback /
link-local ranges. This module centralises that policy so every entry-point
applies the same rules. Domain names are resolved at validation time and every
returned address must be private; otherwise the target is rejected (H-1).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Iterable

logger = logging.getLogger(__name__)

MAX_TARGET_LEN = 253
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])$"
)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class TargetValidationError(ValueError):
    """Raised when a target fails validation."""


def _resolve_all(hostname: str) -> Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    infos = socket.getaddrinfo(hostname, None)
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        # IPv6 addresses may come with a scope id (fe80::1%eth0)
        ip_str = ip_str.split("%", 1)[0]
        try:
            yield ipaddress.ip_address(ip_str)
        except ValueError:
            continue


def validate_target(target: str) -> str:
    """
    Validate a scan target.

    Returns the original target string on success. Raises
    :class:`TargetValidationError` with a human-readable message on rejection.

    Acceptance rules (in order):

    1. String must be non-empty, <= ``MAX_TARGET_LEN`` chars, without
       whitespace, and must not start with ``-`` (prevents argv flag
       injection when later passed to ``nmap``).
    2. ``localhost`` is accepted verbatim.
    3. CIDR ranges must be private/loopback/link-local AND /24 or more
       specific (prefix >= 24).
    4. Bare IPv4 addresses must be private/loopback/link-local/reserved.
    5. Domain names must resolve via DNS and **every** resolved address must
       pass the same private/loopback/link-local test.
    """
    if not isinstance(target, str) or not target:
        raise TargetValidationError("Target cannot be empty.")
    if len(target) > MAX_TARGET_LEN:
        raise TargetValidationError("Target is too long.")
    if target.startswith("-"):
        raise TargetValidationError("Target must not start with '-'.")
    if any(ch.isspace() for ch in target):
        raise TargetValidationError("Target must not contain whitespace.")

    if target == "localhost":
        return target

    if CIDR_RE.match(target):
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen < 24:
            raise TargetValidationError(
                "CIDR prefix must be /24 or more specific."
            )
        if not (net.is_private or net.is_loopback or net.is_link_local):
            raise TargetValidationError(
                "Public IP ranges are not permitted. Only private, loopback, or link-local ranges allowed."
            )
        return target

    if IPV4_RE.match(target):
        addr = ipaddress.ip_address(target)
        if not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved):
            raise TargetValidationError(
                "Public IPs are not permitted. Only private, loopback, or link-local addresses allowed."
            )
        return target

    if DOMAIN_RE.match(target):
        try:
            resolved = list(_resolve_all(target))
        except socket.gaierror:
            raise TargetValidationError(
                f"DNS resolution failed for {target!r}."
            )
        if not resolved:
            raise TargetValidationError(
                f"DNS resolution produced no addresses for {target!r}."
            )
        for addr in resolved:
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                raise TargetValidationError(
                    f"Hostname {target!r} resolves to a public address ({addr}); only private, loopback, or link-local targets are permitted."
                )
        return target

    raise TargetValidationError("Invalid target format.")


# Legacy helper retained for callers in ``src.utils`` that previously imported
# these names. Prefer :func:`validate_target` directly.
def is_valid_ip(ip_str: str) -> tuple[bool, str]:
    try:
        validate_target(ip_str)
        return True, ""
    except TargetValidationError as exc:
        return False, str(exc)

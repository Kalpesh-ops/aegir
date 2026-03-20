import ipaddress
import re


def _parse_ip_or_cidr(
    ip_str: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv4Network, bool]:
    """
    Parse a string as either a bare IPv4 address or a CIDR network.

    Returns:
        (parsed_object, is_cidr) where is_cidr is True for networks, False for addresses.
    """
    if "/" in ip_str:
        return ipaddress.ip_network(ip_str, strict=False), True  # type: ignore[return-value]
    return ipaddress.IPv4Address(ip_str), False


def is_valid_ip(ip_str: str) -> tuple[bool, str]:
    """
    Validate that a string is a valid, routable IP address or CIDR range.

    Returns:
        (True, "") on valid private IP/CIDR.
        (False, "specific error message") on rejection.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "Target cannot be empty."

    if not re.match(r"^[0-9./]+$", ip_str):
        return (
            False,
            "Target contains invalid characters. Only digits, dots, and forward slashes are allowed.",
        )

    try:
        parsed, is_cidr = _parse_ip_or_cidr(ip_str)
    except ValueError:
        return False, "Target is not a valid IP address or CIDR notation."

    if not parsed.version == 4:
        return False, "Only IPv4 addresses are supported."

    if is_cidr and parsed.prefixlen < 24:  # type: ignore[union-attr]
        return (
            False,
            f"Network prefix /{parsed.prefixlen} is too large. Only /24 to /32 are allowed.",  # type: ignore[union-attr]
        )

    first = int(str(parsed.network_address if is_cidr else parsed).split(".")[0])  # type: ignore[union-attr]

    if not is_cidr and str(parsed) == "127.0.0.1":
        return True, ""
    elif first == 10:
        return True, ""
    elif first == 172:
        second = int(str(parsed.network_address if is_cidr else parsed).split(".")[1])  # type: ignore[union-attr]
        if 16 <= second <= 31:
            return True, ""
        return False, (
            f"{ip_str} is not in an allowed private range. "
            "Allowed ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or exactly 127.0.0.1."
        )
    elif first == 192:
        second = int(str(parsed.network_address if is_cidr else parsed).split(".")[1])  # type: ignore[union-attr]
        if second == 168:
            return True, ""
        return False, (
            f"{ip_str} is not in an allowed private range. "
            "Allowed ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or exactly 127.0.0.1."
        )
    else:
        return False, (
            f"{ip_str} is not in an allowed private range. "
            "Allowed ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or exactly 127.0.0.1."
        )


def validate_target(target: str) -> tuple[bool, str]:
    """
    Full target validation combining format and range checks.

    Returns:
        (True, "") on valid target.
        (False, "specific error message") on rejection.
    """
    return is_valid_ip(target)

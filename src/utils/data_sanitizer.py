# Privacy-by-design data sanitization
import re
import copy
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def sanitize_scan_data(scan_data, target=None):
    """
    Privacy-by-design sanitization function.
    Removes PII, masks sensitive data before external processing.

    SANITIZATION RULES:
    1. Strip MAC addresses (AA:BB:CC:DD:EE:FF format)
    2. Mask local IP addresses (if target is external)
    3. Strip email addresses from packet capture
    4. Remove password patterns
    5. Sanitize TShark output

    Args:
        scan_data: dict with scan results
        target: original target IP/hostname (for smart masking)

    Returns:
        Deeply sanitized copy of scan_data
    """
    # Deep copy to avoid modifying original
    sanitized = copy.deepcopy(scan_data)

    # --- REGEX PATTERNS (Strict) ---
    mac_regex = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", re.IGNORECASE)
    email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    password_regex = re.compile(
        r"(?i)(password|passwd|pwd)[:\s=]+[^\s,}]+", re.IGNORECASE
    )
    credential_regex = re.compile(
        r"(?i)(username|user|login)[:\s=]+[^\s,}]+", re.IGNORECASE
    )
    # IPv4 pattern for internal masking
    ipv4_regex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    # Private IP ranges
    private_ip_patterns = [
        re.compile(r"^10\.\d+\.\d+\.\d+$"),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+$"),
        re.compile(r"^192\.168\.\d+\.\d+$"),
        re.compile(r"^127\.\d+\.\d+\.\d+$"),
    ]

    def _is_private_ip(ip):
        """Check if IP is in private range."""
        for pattern in private_ip_patterns:
            if pattern.match(ip):
                return True
        return False

    def _mask_ip(ip):
        """Mask private IP addresses intelligently."""
        if _is_private_ip(ip):
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"
        return ip

    def recursive_clean(obj):
        """Recursively sanitize dict/list structures."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    # Apply sanitization rules
                    sanitized_val = v

                    # Rule 1: Strip MAC addresses
                    sanitized_val = mac_regex.sub("[REDACTED_MAC]", sanitized_val)

                    # Rule 2: Strip email addresses
                    sanitized_val = email_regex.sub("[REDACTED_EMAIL]", sanitized_val)

                    # Rule 3: Strip password patterns
                    sanitized_val = password_regex.sub(
                        "[REDACTED_PASSWORD]", sanitized_val
                    )

                    # Rule 4: Strip username/login patterns
                    sanitized_val = credential_regex.sub(
                        "[REDACTED_CREDENTIAL]", sanitized_val
                    )

                    # Rule 5: Mask internal IP addresses
                    # But preserve the target IP (already known)
                    def mask_ip_func(match):
                        ip = match.group(0)
                        # Don't mask the original target IP
                        if target and (target == ip or target in ip):
                            return ip
                        return _mask_ip(ip)

                    sanitized_val = ipv4_regex.sub(mask_ip_func, sanitized_val)

                    obj[k] = sanitized_val

                elif isinstance(v, (dict, list)):
                    recursive_clean(v)

        elif isinstance(obj, list):
            for item in obj:
                recursive_clean(item)

    # Apply recursive sanitization
    recursive_clean(sanitized)

    logging.info("Data sanitization complete (PII removed)")
    return sanitized


def redact_enriched_scan(data: dict) -> dict:
    """
    Redact PII from enriched scan results while preserving CVE and port data intact.

    Redacts only:
      - "target" field (top-level string): replaced with "REDACTED_IP"
      - "hostname" / "hostnames" string fields: replaced with "REDACTED_HOST"
      - "mac_address" string fields: replaced with "REDACTED_MAC"

    Preserves unchanged (no string scanning):
      - All port object fields: port, protocol, service, product, version, state,
        cves, cvss, summary, description, cve_id, and every other field
      - All CVE object fields
      - All nested arrays and objects not listed above

    Args:
        data: dict with optional "ports" (list of port objects) and
            "cve_findings" (list of CVE objects) keys.

    Returns:
        A deeply redacted copy of data. The original is not mutated.
    """
    redacted = copy.deepcopy(data)

    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", re.IGNORECASE)

    def walk(obj: any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Skip ports arrays and CVE data entirely
                if key in ("ports", "cves"):
                    continue
                # Redact specific known sensitive fields
                if key == "target" and isinstance(value, str):
                    obj[key] = "REDACTED_IP"
                elif key in ("hostname", "hostnames") and isinstance(value, str):
                    obj[key] = "REDACTED_HOST"
                elif key == "mac_address" and isinstance(value, str):
                    obj[key] = mac_pattern.sub("[REDACTED_MAC]", value)
                elif isinstance(value, (dict, list)):
                    walk(value)
                # Leave all other string values untouched
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(redacted)
    return redacted


def redact_report_text(report_text: str) -> str:
    """
    Second-pass redactor for AI-generated prose that is about to be written to
    the cross-tenant global cache (M-1). The model sometimes quotes back IPs,
    hostnames, emails, MAC addresses or credentials that appeared in the scan;
    those must not leak across users who hit the same cache signature.

    The input is assumed to already have been through :func:`sanitize_scan_data`
    on the way *in*; this function handles the symmetric problem on the way
    *out*.
    """
    if not isinstance(report_text, str) or not report_text:
        return report_text

    mac_regex = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", re.IGNORECASE)
    email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    ipv4_regex = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    password_regex = re.compile(r"(?i)(password|passwd|pwd)[:\s=]+\S+")
    credential_regex = re.compile(r"(?i)(username|user|login)[:\s=]+\S+")

    out = mac_regex.sub("[REDACTED_MAC]", report_text)
    out = email_regex.sub("[REDACTED_EMAIL]", out)
    out = ipv4_regex.sub("[REDACTED_IP]", out)
    out = password_regex.sub(r"\1 [REDACTED]", out)
    out = credential_regex.sub(r"\1 [REDACTED]", out)
    return out


def redact_target_for_storage(target: str) -> str:
    """
    Return a display-safe rendering of ``target`` for the ``scans`` table.

    The column was previously called ``target_redacted`` but stored the raw
    value — a misleading name that looked like a privacy guarantee it didn't
    provide (M-11). This helper masks the final octet of private IPv4s and
    collapses hostnames to their eTLD+1 so a shared screenshot of scan
    history does not reveal the exact host scanned.
    """
    if not target:
        return target
    candidate = target.strip()
    if not candidate:
        return candidate

    # Loopback and "localhost" are already as uninformative as they get.
    if candidate.lower() in {"localhost", "::1"}:
        return candidate

    ipv4 = re.fullmatch(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)",
        candidate,
    )
    if ipv4:
        parts = candidate.split(".")
        return ".".join(parts[:3] + ["XXX"])

    cidr = re.fullmatch(
        r"((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))/(\d{1,2})",
        candidate,
    )
    if cidr:
        parts = cidr.group(1).split(".")
        return ".".join(parts[:3] + ["XXX"]) + f"/{cidr.group(2)}"

    # For hostnames keep only the registrable-looking trailing components.
    labels = candidate.split(".")
    if len(labels) >= 2:
        return "***." + ".".join(labels[-2:])
    return "***"

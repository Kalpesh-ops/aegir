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
    email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
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
    Redact PII from enriched scan results while preserving CVE data intact.

    Redacts:
      - The "target" field: replaced with "REDACTED_IP"
      - Hostname fields: replaced with "REDACTED_HOST"
      - MAC addresses: replaced with "REDACTED_MAC"

    Preserves (not modified):
      - Port numbers, service names, product, version, state
      - All fields inside "cves" arrays: cve_id, cvss, summary

    Args:
        data: Enriched scan result dict with optional "target", "hosts", and
            "cve_findings" keys.

    Returns:
        A deeply redacted copy of data. The original is not mutated.
    """
    redacted = copy.deepcopy(data)

    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", re.IGNORECASE)

    def redact_str(value: str) -> str:
        return mac_pattern.sub("[REDACTED_MAC]", value)

    def walk(obj: any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "cves":
                    continue
                if key == "target" and isinstance(value, str):
                    obj[key] = "REDACTED_IP"
                elif key in ("hostname", "hostnames"):
                    obj[key] = "REDACTED_HOST"
                elif isinstance(value, str):
                    obj[key] = redact_str(value)
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(redacted)
    return redacted

from src.utils.data_sanitizer import (
    redact_enriched_scan,
    redact_report_text,
    redact_target_for_storage,
    sanitize_scan_data,
)


def test_redact_report_text_scrubs_ips_and_pii() -> None:
    raw = (
        "Attacker could pivot from 192.168.1.50 using creds alice@example.com / "
        "password: hunter2. MAC AA:BB:CC:DD:EE:FF is exposed."
    )
    redacted = redact_report_text(raw)
    assert "192.168.1.50" not in redacted
    assert "alice@example.com" not in redacted
    assert "hunter2" not in redacted
    assert "AA:BB:CC:DD:EE:FF" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_MAC]" in redacted


def test_redact_report_text_empty() -> None:
    assert redact_report_text("") == ""
    assert redact_report_text(None) is None  # type: ignore[arg-type]


def test_redact_enriched_scan_strips_target_and_mac() -> None:
    scan = {
        "target": "192.168.1.50",
        "hostname": "alice-laptop.local",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ports": [
            {"port": 22, "service": "ssh"},
        ],
    }
    out = redact_enriched_scan(scan)
    assert out["target"] != "192.168.1.50"
    assert out["hostname"] != "alice-laptop.local"
    assert out["mac_address"] != "aa:bb:cc:dd:ee:ff"
    # Ports are structural — should NOT be redacted
    assert out["ports"][0]["port"] == 22


def test_sanitize_scan_data_roundtrip() -> None:
    scan = {
        "nmap_output": "Host is up (10.0.0.1)\nMAC Address: AA:BB:CC:DD:EE:FF",
        "target": "10.0.0.1",
    }
    cleaned = sanitize_scan_data(scan)
    assert "AA:BB:CC:DD:EE:FF" not in cleaned["nmap_output"]


def test_redact_target_for_storage_ipv4_masks_last_octet() -> None:
    assert redact_target_for_storage("192.168.1.50") == "192.168.1.XXX"
    assert redact_target_for_storage("10.0.0.5") == "10.0.0.XXX"


def test_redact_target_for_storage_cidr_masks_last_octet() -> None:
    assert redact_target_for_storage("192.168.1.0/24") == "192.168.1.XXX/24"


def test_redact_target_for_storage_hostname_keeps_suffix() -> None:
    assert redact_target_for_storage("box.internal.example.com") == "***.example.com"
    assert redact_target_for_storage("server.lan") == "***.server.lan"


def test_redact_target_for_storage_preserves_loopback() -> None:
    assert redact_target_for_storage("localhost") == "localhost"
    assert redact_target_for_storage("127.0.0.1") == "127.0.0.XXX"

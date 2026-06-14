"""Worker pipeline helpers with fully faked engines (no network, no nmap)."""

from __future__ import annotations

import pytest

pytest.importorskip("nmap")
pytest.importorskip("google.generativeai")

from src.queue import worker


def test_flatten_cves_injects_port_context():
    enriched = [
        {
            "portid": 21,
            "protocol": "tcp",
            "service": "ftp",
            "cves": [{"cve_id": "CVE-2011-2523"}],
        }
    ]
    out = worker._flatten_cves(enriched)
    assert out == [
        {"cve_id": "CVE-2011-2523", "port": 21, "protocol": "tcp", "service": "ftp"}
    ]


def test_flatten_cves_handles_alternate_field_names():
    enriched = [
        {"port_number": 80, "proto": "tcp", "name": "http", "cves": [{"cve_id": "CVE-1"}]}
    ]
    out = worker._flatten_cves(enriched)
    assert out[0]["port"] == 80
    assert out[0]["protocol"] == "tcp"
    assert out[0]["service"] == "http"


def test_merge_cves_dedupes_by_id_primary_wins():
    primary = [{"cve_id": "CVE-1", "source": "vulnchecker"}]
    extra = [{"cve_id": "CVE-1", "source": "circl"}, {"cve_id": "CVE-2", "source": "circl"}]

    merged = worker._merge_cves(primary, extra)

    assert len(merged) == 2
    cve1 = next(c for c in merged if c["cve_id"] == "CVE-1")
    assert cve1["source"] == "vulnchecker"  # primary kept, extra dropped
    assert any(c["cve_id"] == "CVE-2" for c in merged)


def test_infer_firewall_filtered_ports_means_stateful():
    scan_data = {"hosts": [{"open_ports": [{"state": "filtered"}, {"state": "open"}]}]}
    result = worker._infer_firewall_from_nmap(scan_data, "10.0.0.1")
    assert "Filtered" in result["firewall_status"]
    assert result["inference_method"] == "nmap_fallback"


def test_infer_firewall_no_hosts_is_unknown():
    result = worker._infer_firewall_from_nmap({"hosts": []}, "10.0.0.1")
    assert result["firewall_status"] == "Unknown"


def test_run_fast_pipeline_enriches_and_flattens():
    class FakeScanner:
        def parse_ports_from_xml(self, xml):
            return [{"portid": 21, "service": "ftp"}]

    class FakeCircl:
        def enrich_services(self, ports):
            return [{"portid": 21, "service": "ftp", "cves": [{"cve_id": "CVE-2011-2523"}]}]

    enriched, cves, extra = worker._run_fast_pipeline(
        FakeScanner(), FakeCircl(), "10.0.0.1", "<xml/>"
    )
    assert enriched[0]["portid"] == 21
    assert cves[0]["cve_id"] == "CVE-2011-2523"
    assert extra == {}


def test_probe_firewall_falls_back_to_nmap_on_scapy_error(monkeypatch):
    """When Scapy returns an error dict, the Nmap inference path must run."""

    class FakeScapy:
        def firewall_detect(self, target, port):
            return {"error": "admin_required"}

    monkeypatch.setattr(worker, "ScapyEngine", FakeScapy)

    scan_data = {"hosts": [{"open_ports": [{"state": "filtered"}]}]}
    result = worker._probe_firewall("10.0.0.1", 445, scan_data, "PenTest")
    assert result["inference_method"] == "nmap_fallback"


def test_probe_firewall_uses_scapy_when_available(monkeypatch):
    class FakeScapy:
        def firewall_detect(self, target, port):
            return {"firewall_status": "Stateless / Unfiltered (Less Secure)"}

    monkeypatch.setattr(worker, "ScapyEngine", FakeScapy)

    result = worker._probe_firewall("10.0.0.1", 80, {}, "Deep")
    assert result["inference_method"] == "scapy_direct"
    assert "Stateless" in result["firewall_status"]

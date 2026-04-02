import time
import logging

from src.queue.job_manager import (
    get_next_job,
    mark_running,
    mark_complete,
    mark_failed,
    get_job_status,
)
from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.scanner.tshark_engine import TSharkScanner
from src.vuln_lookup.circl_client import CIRCLClient
from src.vuln_lookup.vuln_checker import VulnChecker
from src.utils.data_sanitizer import redact_enriched_scan
from src.ai_agent.gemini_client import GeminiAgent
from src.database.supabase_client import store_scan_result

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def _flatten_cves(enriched_ports: list) -> list:
    """Extract and flatten CVEs from enriched port list, injecting port context."""
    cve_findings = []
    for port in enriched_ports:
        for cve in port.get("cves", []):
            cve_copy = dict(cve)
            cve_copy["port"] = port.get("portid") or port.get("port") or port.get("port_number")
            cve_copy["protocol"] = port.get("protocol") or port.get("proto")
            cve_copy["service"] = port.get("service") or port.get("service_name") or port.get("name")
            cve_findings.append(cve_copy)
    return cve_findings


def _run_fast_pipeline(scanner, circl, target, xml_output):
    """
    FAST: nmap (quick flags) → CIRCL CVE enrichment → return
    """
    ports = scanner.parse_ports_from_xml(xml_output)
    enriched = circl.enrich_services(ports)
    cve_findings = _flatten_cves(enriched)
    return enriched, cve_findings, {}


def _run_deep_pipeline(scanner, circl, target, xml_output, scan_data):
    """
    DEEP: nmap (default scripts) → VulnChecker (script CVEs + CIRCL) → Scapy firewall probe
    """
    ports = scanner.parse_ports_from_xml(xml_output)

    # VulnChecker: Phase 1 (script output CVEs) + Phase 2 (CIRCL lookup)
    checker = VulnChecker()
    script_and_circl_cves = checker.extract_cves(scan_data)

    # Also enrich via CIRCL directly for port-level data
    enriched = circl.enrich_services(ports)
    flat_cves = _flatten_cves(enriched)

    # Merge: prefer VulnChecker results (richer), deduplicate by cve_id
    seen = {c.get("cve_id") for c in script_and_circl_cves if c.get("cve_id")}
    for c in flat_cves:
        if c.get("cve_id") not in seen:
            script_and_circl_cves.append(c)
            seen.add(c.get("cve_id"))

    # Scapy firewall probe with Nmap inference fallback
    firewall_result = {}
    try:
        scapy = ScapyEngine()
        fw = scapy.firewall_detect(target, port=80)
        if "error" in fw:
            raise PermissionError(fw["error"])
        fw["inference_method"] = "scapy_direct"
        firewall_result = fw
        logging.info(f"[Worker][Deep] Scapy firewall result: {fw['firewall_status']}")
    except Exception as e:
        logging.warning(f"[Worker][Deep] Scapy failed ({e}), falling back to Nmap inference")
        firewall_result = _infer_firewall_from_nmap(scan_data, target)

    return enriched, script_and_circl_cves, {"firewall": firewall_result}


def _run_pen_test_pipeline(scanner, circl, target, xml_output, scan_data):
    """
    PEN_TEST: nmap (all ports) → VulnChecker → Scapy firewall → TShark capture
    """
    ports = scanner.parse_ports_from_xml(xml_output)

    checker = VulnChecker()
    cve_findings = checker.extract_cves(scan_data)

    enriched = circl.enrich_services(ports)
    flat_cves = _flatten_cves(enriched)
    seen = {c.get("cve_id") for c in cve_findings if c.get("cve_id")}
    for c in flat_cves:
        if c.get("cve_id") not in seen:
            cve_findings.append(c)
            seen.add(c.get("cve_id"))

    # Scapy - probe SMB port for pen_test
    firewall_result = {}
    try:
        scapy = ScapyEngine()
        fw = scapy.firewall_detect(target, port=445)
        if "error" in fw:
            raise PermissionError(fw["error"])
        fw["inference_method"] = "scapy_direct"
        firewall_result = fw
    except Exception as e:
        logging.warning(f"[Worker][PenTest] Scapy failed ({e}), using Nmap inference")
        firewall_result = _infer_firewall_from_nmap(scan_data, target)

    # TShark — 30s capture, auto-detects interface from target subnet
    tshark_result = {}
    try:
        tshark = TSharkScanner()
        tshark_result = tshark.run_capture(target_ip=target, duration=30)
        if tshark_result.get("status") not in ("captured",):
            logging.warning(f"[Worker][PenTest] TShark non-fatal: {tshark_result.get('error')}")
            tshark_result = {"status": "unavailable", "reason": tshark_result.get("error")}
        else:
            logging.info(f"[Worker][PenTest] TShark captured {tshark_result.get('size_bytes')} bytes")
    except Exception as e:
        logging.warning(f"[Worker][PenTest] TShark failed (non-fatal): {e}")
        tshark_result = {"status": "unavailable", "reason": str(e)}

    extra = {"firewall": firewall_result, "traffic": tshark_result}
    return enriched, cve_findings, extra


def _infer_firewall_from_nmap(scan_data: dict, target: str) -> dict:
    """Minimal Nmap port-state based firewall inference (fallback)."""
    try:
        hosts = scan_data.get("hosts", [])
        if not hosts:
            return {"firewall_status": "Unknown", "inference_method": "nmap_fallback"}
        port_states = {}
        for host in hosts:
            for p in host.get("open_ports", []):
                state = p.get("state", "unknown")
                port_states[state] = port_states.get(state, 0) + 1
        filtered = port_states.get("filtered", 0)
        if filtered > 0:
            return {
                "firewall_status": "Stateful / Filtered (Secure)",
                "inference_method": "nmap_fallback",
                "port_breakdown": port_states,
            }
        return {
            "firewall_status": "Stateless / Unfiltered (Inferred)",
            "inference_method": "nmap_fallback",
            "port_breakdown": port_states,
        }
    except Exception:
        return {"firewall_status": "Unknown", "inference_method": "nmap_fallback"}


def run_worker() -> None:
    scanner = NmapScanner()
    circl = CIRCLClient()

    while True:
        try:
            job = get_next_job()
            if job is None:
                time.sleep(3)
                continue

            job_id = job["job_id"]
            target = job["target"]
            scan_mode = job.get("scan_mode") or "fast"
            logging.info(f"[Worker] Job {job_id} | target={target} | mode={scan_mode}")

            mark_running(job_id)

            try:
                scan_result = scanner.run_scan(target, mode=scan_mode)
                if isinstance(scan_result, dict) and "error" in scan_result:
                    raise Exception(scan_result["error"])

                xml_output = scan_result["xml"]
                scan_data = scan_result.get("data", {})

                # --- Mode-aware pipeline ---
                if scan_mode == "deep":
                    enriched, cve_findings, extra = _run_deep_pipeline(
                        scanner, circl, target, xml_output, scan_data
                    )
                elif scan_mode == "pen_test":
                    enriched, cve_findings, extra = _run_pen_test_pipeline(
                        scanner, circl, target, xml_output, scan_data
                    )
                else:
                    enriched, cve_findings, extra = _run_fast_pipeline(
                        scanner, circl, target, xml_output
                    )

                redacted = redact_enriched_scan(
                    {"ports": enriched, "cve_findings": cve_findings}
                )

                ai_agent = GeminiAgent()
                ai_summary = ai_agent.analyze_scan(
                    redacted["ports"],
                    redacted["cve_findings"],
                )

                result = {
                    "ports": redacted["ports"],
                    "cve_findings": redacted["cve_findings"],
                    "ai_summary": ai_summary,
                    **extra,  # firewall and/or traffic data per mode
                }

                mark_complete(job_id, result)

                try:
                    job_info = get_job_status(job_id)
                    user_id = job_info.get("user_id", "anonymous") if job_info else "anonymous"
                    store_scan_result(
                        user_id=user_id,
                        target_redacted=target,
                        ports=redacted["ports"],
                        cve_findings=redacted["cve_findings"],
                        ai_summary=ai_summary,
                        scan_mode=scan_mode,  # ← now persisted to Supabase
                    )
                except Exception as sb_err:
                    logging.error(f"[Worker] Supabase store failed (non-fatal): {sb_err}")

                logging.info(f"[Worker] Job {job_id} complete")

            except Exception as e:
                logging.error(f"[Worker] Job {job_id} failed: {e}")
                mark_failed(job_id, "Scan pipeline failed. Check server logs.")

        except Exception as e:
            logging.error(f"[Worker] Outer loop error: {e}")
            time.sleep(3)

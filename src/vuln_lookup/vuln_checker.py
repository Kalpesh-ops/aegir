import re
import logging
from src.vuln_lookup.circl_client import CIRCLClient

logger = logging.getLogger(__name__)


class VulnChecker:

    def __init__(self):
        self.circl = CIRCLClient()

    def extract_cves(self, nmap_data: dict) -> list:
        """
        Two-phase CVE extraction:

        Phase 1 — Script output (deep/pen_test mode only):
            Regex-match CVE-YYYY-NNNN strings from nmap --script vuln output.

        Phase 2 — CIRCL API lookup (all modes):
            For every open port with a known product/service, query the CIRCL
            CVE database. This is the primary source for fast-mode scans where
            --script vuln was not run.

        Returns a deduplicated list of vulnerability dicts, each with:
            port, service, product, version, cve_id, cvss, summary, source
        """
        if "hosts" not in nmap_data:
            return []

        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        results = []
        seen_cve_ids = set()

        for host in nmap_data["hosts"]:
            for port in host.get("open_ports", []):
                port_num  = port.get("port", "unknown")
                service   = port.get("service", "unknown")
                product   = port.get("product", "unknown")
                version   = port.get("version", "unknown")

                # ── Phase 1: nmap script output ──────────────────────────────
                script_output = port.get("vulnerabilities_found", "")
                if script_output:
                    cves_in_script = cve_pattern.findall(script_output)
                    for cve_id in set(cves_in_script):
                        if cve_id not in seen_cve_ids:
                            seen_cve_ids.add(cve_id)
                            results.append({
                                "port":    port_num,
                                "service": service,
                                "product": product,
                                "version": version,
                                "cve_id":  cve_id,
                                "cvss":    None,
                                "summary": f"Detected in nmap script output",
                                "source":  "nmap_script",
                            })

                # ── Phase 2: CIRCL API lookup ─────────────────────────────────
                # FIX: This was completely missing before — CIRCL was never called.
                try:
                    vendor_str, product_str = self.circl._derive_vendor_product(port)
                    if vendor_str == "unknown":
                        continue

                    cve_list = self.circl.lookup_cves(vendor_str, product_str)
                    for cve in cve_list:
                        cve_id = cve.get("cve_id", "")
                        if not cve_id:
                            continue
                        if cve_id in seen_cve_ids:
                            continue
                        seen_cve_ids.add(cve_id)
                        results.append({
                            "port":    port_num,
                            "service": service,
                            "product": product,
                            "version": version,
                            "cve_id":  cve_id,
                            "cvss":    cve.get("cvss"),
                            "summary": cve.get("summary", ""),
                            "source":  "circl",
                        })
                except Exception as e:
                    logger.warning(f"[VulnChecker] CIRCL lookup failed for port {port_num}: {e}")
                    continue

        logger.info(f"[VulnChecker] Total CVEs found: {len(results)}")
        return results

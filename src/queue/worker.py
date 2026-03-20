import copy
import time
import json
import logging

from src.queue.job_manager import (
    get_next_job,
    mark_running,
    mark_complete,
    mark_failed,
    get_job_status,
)
from src.scanner.nmap_engine import NmapScanner
from src.vuln_lookup.circl_client import CIRCLClient
from src.utils.data_sanitizer import sanitize_scan_data, redact_enriched_scan
from src.ai_agent.gemini_client import GeminiAgent
from src.database.supabase_client import store_scan_result

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def run_worker() -> None:
    """
    Long-running worker loop that processes scan jobs from the queue.

    Each iteration:
      1. Fetch the oldest queued job via get_next_job().
      2. Mark it running.
      3. Execute the full pipeline:
         a. Nmap scan
         b. CVE enrichment (CIRCL)
         c. Data sanitization
         d. AI analysis (Gemini)
      4. Store the result with mark_complete() or the error with mark_failed().
      5. Sleep 3 seconds and repeat.

    The outer loop never crashes.
    """
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
            logging.info(f"[Worker] Processing job {job_id} targeting {target}")

            mark_running(job_id)

            try:
                scan_result = scanner.run_scan(target, mode="fast")

                if isinstance(scan_result, dict) and "error" in scan_result:
                    raise Exception(scan_result["error"])

                xml_output = scan_result["xml"]
                structured_data = scan_result["data"]

                ports = scanner.parse_ports_from_xml(xml_output)
                enriched = circl.enrich_services(ports)

                cve_findings = [
                    cve for port in enriched for cve in port.get("cves", [])
                ]

                enriched_for_gemini = redact_enriched_scan(
                    {"ports": enriched, "cve_findings": cve_findings}
                )

                structured_for_storage = copy.deepcopy(structured_data)
                structured_for_storage["target"] = "REDACTED_IP"
                for host in structured_for_storage.get("hosts", []):
                    host["ip"] = "REDACTED_IP"

                ai_agent = GeminiAgent()
                ai_summary = ai_agent.analyze_scan(
                    enriched_for_gemini["ports"],
                    enriched_for_gemini["cve_findings"],
                )

                result = {
                    "ports": structured_for_storage,
                    "cve_findings": cve_findings,
                    "ai_summary": ai_summary,
                }

                mark_complete(job_id, result)
                try:
                    job = get_job_status(job_id)
                    user_id = job.get("user_id", "anonymous") if job else "anonymous"
                    store_scan_result(
                        user_id=user_id,
                        target_redacted=target,
                        ports=enriched_for_gemini["ports"],
                        cve_findings=enriched_for_gemini["cve_findings"],
                        ai_summary=ai_summary,
                    )
                except Exception as sb_err:
                    logging.error(
                        f"[Worker] Supabase store failed (non-fatal): {sb_err}"
                    )
                logging.info(f"[Worker] Job {job_id} complete")

            except Exception as e:
                logging.error(f"[Worker] Job {job_id} failed: {e}")
                mark_failed(job_id, "Scan pipeline failed. Check server logs.")

        except Exception as e:
            logging.error(f"[Worker] Outer loop error: {e}")
            time.sleep(3)

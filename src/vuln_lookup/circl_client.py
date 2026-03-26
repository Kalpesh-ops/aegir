import os
import sqlite3
import time
import requests
import logging
import socket

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
CACHE_DB = os.path.join(CACHE_DIR, "cve_cache.db")
CACHE_TTL_DAYS = 7

CIRCL_URLS = [
    "https://cve.circl.lu/api/search",
    "https://vulnerability.circl.lu/api/search",
]


def _get_cache_conn() -> sqlite3.Connection:
    os.makedirs(CACHE_DIR, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_cache "
        "(vendor TEXT, product TEXT, result_json TEXT, cached_at TEXT, "
        "PRIMARY KEY (vendor, product))"
    )
    conn.commit()
    conn.close()
    return sqlite3.connect(CACHE_DB)


class CIRCLClient:
    def __init__(self):
        self.api_base = self._resolve_api_base()

    def _resolve_api_base(self) -> str:
        """Resolve API base URL with DNS fallback."""
        hostnames = ["cve.circl.lu", "vulnerability.circl.lu"]
        for hostname in hostnames:
            try:
                socket.getaddrinfo(hostname, 443)
                logging.info(f"[CVE] DNS resolved: {hostname}")
                return f"https://{hostname}/api/search"
            except socket.gaierror:
                logging.warning(f"[CVE] DNS failed for {hostname}, trying fallback...")
                continue
        logging.warning("[CVE] CIRCL DNS resolution failed for all hostnames, using default")
        return CIRCL_URLS[0]

    def test_connection(self) -> bool:
        """Test if CIRCL API is reachable."""
        try:
            base = self.api_base.replace("/search", "")
            r = requests.get(f"{base}/dbInfo", timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def lookup_cves(self, vendor: str, product: str) -> list:
        """
        Look up CVEs for a given vendor and product via the CIRCL API.
        Results are cached in SQLite for 7 days.

        CIRCL API endpoint: /api/search/{vendor}/{product}
        Example: /api/search/vsftpd/vsftpd
        """
        if not vendor or vendor == "unknown":
            return []

        if not product or product == "unknown":
            product = vendor

        cached = self._cache_get(vendor, product)
        if cached is not None:
            return cached

        result = self._fetch_cves(vendor, product)
        self._cache_put(vendor, product, result)
        return result

    def _fetch_cves(self, vendor: str, product: str) -> list:
        """Call the CIRCL API with fallback URLs and return parsed CVE results."""
        response = None
        for base_url in CIRCL_URLS:
            try:
                url = f"{base_url}/{vendor}/{product}"
                logging.info(f"[CVE] Querying: {url}")
                response = requests.get(url, timeout=15)
                response.raise_for_status()
                break
            except requests.Timeout:
                logging.warning(f"[CVE] Timeout for {vendor}/{product} at {base_url}")
                continue
            except Exception as e:
                logging.warning(f"[CVE] Request failed for {vendor}/{product}: {e}")
                continue
        else:
            logging.warning(f"[CVE] All URLs failed for {vendor}/{product}")
            return []

        try:
            data = response.json()
        except Exception:
            logging.warning(f"[CVE] Failed to parse JSON for {vendor}/{product}")
            return []

        # ── Parse the CIRCL v2 response format ───────────────────────────────
        #
        # Response structure:
        # {
        #   "results": {
        #     "cvelistv5": [["CVE-XXXX-YYYY", { full CVE record }], ...],
        #     "nvd":       [["CVE-XXXX-YYYY", { full CVE record }], ...]
        #   },
        #   "total_count": N
        # }
        #
        # Each entry is a 2-element list: [cve_id_string, cve_record_dict]
        # We prefer "nvd" (has CVSS scores); fall back to "cvelistv5".
        # ─────────────────────────────────────────────────────────────────────

        raw_results = data.get("results", {})

        entries = []
        if isinstance(raw_results, dict):
            # Prefer nvd (has CVSS), fall back to cvelistv5
            for source in ("nvd", "cvelistv5"):
                source_entries = raw_results.get(source, [])
                if source_entries:
                    entries = source_entries
                    break
        elif isinstance(raw_results, list):
            # Old flat-list format
            entries = raw_results

        if not entries:
            logging.info(f"[CVE] No CVEs found for {vendor}/{product}")
            return []

        cves = []
        seen_ids = set()

        for entry in entries:
            try:
                # ── New format: ["cve-2011-2523", { record dict }] ──
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    cve_id_raw, record = entry
                    cve_id = cve_id_raw.upper()

                    if cve_id in seen_ids:
                        continue
                    seen_ids.add(cve_id)

                    # Extract English description
                    summary = ""
                    try:
                        descs = (
                            record.get("containers", {})
                                  .get("cna", {})
                                  .get("descriptions", [])
                        )
                        for d in descs:
                            if d.get("lang", "").startswith("en"):
                                summary = d.get("value", "")
                                break
                    except Exception:
                        pass

                    # Extract CVSS base score
                    cvss = 0.0
                    try:
                        metrics = (
                            record.get("containers", {})
                                  .get("cna", {})
                                  .get("metrics", [])
                        )
                        for metric in metrics:
                            for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                                if key in metric:
                                    cvss = float(metric[key].get("baseScore", 0.0))
                                    break
                            if cvss:
                                break
                    except Exception:
                        pass

                    cves.append({"cve_id": cve_id, "cvss": cvss, "summary": summary})

                # ── Old flat-dict format (backwards compat) ──
                elif isinstance(entry, dict):
                    cve_id = entry.get("id", "").upper()
                    if not cve_id or cve_id in seen_ids:
                        continue
                    seen_ids.add(cve_id)
                    cvss = 0.0
                    try:
                        cvss = float(entry.get("cvss", 0.0))
                    except (ValueError, TypeError):
                        pass
                    cves.append({
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "summary": entry.get("summary", ""),
                    })

            except Exception as e:
                logging.debug(f"[CVE] Skipping malformed entry: {e}")
                continue

        cves.sort(key=lambda x: x["cvss"], reverse=True)
        top = cves[:5]
        logging.info(f"[CVE] {len(top)} CVEs returned for {vendor}/{product}")
        return top

    def _cache_get(self, vendor: str, product: str) -> list | None:
        """Return cached result if it exists and is less than 7 days old."""
        import json
        try:
            conn = _get_cache_conn()
            cursor = conn.execute(
                "SELECT result_json, cached_at FROM cve_cache "
                "WHERE vendor = ? AND product = ?",
                (vendor, product),
            )
            row = cursor.fetchone()
            conn.close()
            if row is None:
                return None
            result_json, cached_at = row
            if time.time() - float(cached_at) > CACHE_TTL_DAYS * 86400:
                return None
            return json.loads(result_json)
        except Exception:
            return None

    def _cache_put(self, vendor: str, product: str, result: list) -> None:
        """Write result to the SQLite cache."""
        import json
        try:
            conn = _get_cache_conn()
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (vendor, product, result_json, cached_at) "
                "VALUES (?, ?, ?, ?)",
                (vendor, product, json.dumps(result), str(time.time())),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logging.warning(f"[CVE] Failed to write to CVE cache: {e}")

    def enrich_services(self, services: list) -> list:
        """Enrich a list of service dicts with CVE data."""
        for svc in services:
            try:
                vendor, product = self._derive_vendor_product(svc)
                svc["cves"] = self.lookup_cves(vendor, product)
            except Exception:
                svc["cves"] = []
        return services

    def _derive_vendor_product(self, svc: dict) -> tuple[str, str]:
        """Map nmap product/service strings to CIRCL vendor/product pairs."""
        nmap_product = svc.get("product", "unknown").strip()
        nmap_service = svc.get("service", "unknown").strip()

        def normalise(s: str) -> str:
            return s.lower().replace(" ", "_").replace("-", "_")

        KNOWN = {
            "apache httpd":       ("apache", "http_server"),
            "apache http server": ("apache", "http_server"),
            "openssh":            ("openssh", "openssh"),
            "vsftpd":             ("vsftpd", "vsftpd"),
            "mysql":              ("mysql", "mysql"),
            "postgresql":         ("postgresql", "postgresql"),
            "samba smbd":         ("samba", "samba"),
            "samba":              ("samba", "samba"),
            "microsoft-ds":       ("microsoft", "windows"),
            "proftpd":            ("proftpd", "proftpd"),
            "pure-ftpd":          ("pure-ftpd", "pure-ftpd"),
            "nginx":              ("nginx", "nginx"),
            "isc bind":           ("isc", "bind"),
            "bind":               ("isc", "bind"),
            "postfix smtpd":      ("postfix", "postfix"),
            "exim":               ("exim", "exim"),
            "dovecot":            ("dovecot", "dovecot"),
            "vnc":                ("realvnc", "vnc"),
            "x11":                ("x.org", "x11"),
        }

        key = nmap_product.lower()
        if key in KNOWN:
            return KNOWN[key]

        for known_key, mapping in KNOWN.items():
            if known_key in key or key in known_key:
                return mapping

        if nmap_product and nmap_product.lower() != "unknown":
            norm = normalise(nmap_product)
            return (norm, norm)

        if nmap_service and nmap_service.lower() != "unknown":
            norm = normalise(nmap_service)
            return (norm, norm)

        return ("unknown", "unknown")

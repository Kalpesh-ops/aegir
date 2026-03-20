import os
import sqlite3
import time
import requests
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
CACHE_DB = os.path.join(CACHE_DIR, "cve_cache.db")
CACHE_TTL_DAYS = 7


def _get_cache_conn() -> sqlite3.Connection:
    os.makedirs(CACHE_DIR, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cve_cache "
        "(service TEXT, version TEXT, result_json TEXT, cached_at TEXT, "
        "PRIMARY KEY (service, version))"
    )
    conn.close()
    return sqlite3.connect(CACHE_DB)


class CIRCLClient:
    BASE_URL = "https://cve.circl.lu/api/search"

    def lookup_cves(self, service: str, version: str) -> list:
        """
        Look up CVEs for a given service and version via the CIRCL API.
        Results are cached in SQLite for 7 days.

        Args:
            service: Service name (e.g. "apache", "mysql")
            version: Version string (e.g. "2.4.41"). If "unknown", returns [].

        Returns:
            List of dicts with keys: cve_id, cvss, summary.
            Top 5 results sorted by cvss descending.
            Returns [] on timeout (5 seconds), empty response, or error.
        """
        if version == "unknown":
            return []

        cached = self._cache_get(service, version)
        if cached is not None:
            return cached

        result = self._fetch_cves(service, version)
        self._cache_put(service, version, result)
        return result

    def _fetch_cves(self, service: str, version: str) -> list:
        """Call the CIRCL API and return parsed CVE results."""
        try:
            url = f"{self.BASE_URL}/{service}/{version}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.Timeout:
            logging.warning(f"CIRCL API timeout for {service}/{version}")
            return []
        except Exception:
            return []

        try:
            data = response.json()
        except Exception:
            return []

        if not isinstance(data, dict) or "results" not in data:
            return []

        results = data["results"]

        cves = []
        for entry in results:
            try:
                cve_id = entry.get("id", "")
                summary = entry.get("summary", "")
                cvss = 0.0
                if "cvss" in entry:
                    try:
                        cvss = float(entry["cvss"])
                    except (ValueError, TypeError):
                        cvss = 0.0

                cves.append({"cve_id": cve_id, "cvss": cvss, "summary": summary})
            except Exception:
                continue

        cves.sort(key=lambda x: x["cvss"], reverse=True)
        return cves[:5]

    def _cache_get(self, service: str, version: str) -> list | None:
        """Return cached result if it exists and is less than 7 days old."""
        import json

        try:
            conn = _get_cache_conn()
            cursor = conn.execute(
                "SELECT result_json, cached_at FROM cve_cache "
                "WHERE service = ? AND version = ?",
                (service, version),
            )
            row = cursor.fetchone()
            conn.close()
            if row is None:
                return None

            result_json, cached_at = row
            cached_time = float(cached_at)
            if time.time() - cached_time > CACHE_TTL_DAYS * 86400:
                return None

            return json.loads(result_json)
        except Exception:
            return None

    def _cache_put(self, service: str, version: str, result: list) -> None:
        """Write result to the SQLite cache."""
        import json

        try:
            conn = _get_cache_conn()
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (service, version, result_json, cached_at) "
                "VALUES (?, ?, ?, ?)",
                (service, version, json.dumps(result), str(time.time())),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logging.warning(f"Failed to write to CVE cache: {e}")

    def enrich_services(self, services: list) -> list:
        """
        Enrich a list of service dicts with CVE data.

        Args:
            services: List of dicts with keys port, protocol, service, product,
                version, state (as produced by parse_ports_from_xml).

        Returns:
            The same list with an added "cves" key on each dict containing the
            result of lookup_cves(service, version).
        """
        for svc in services:
            try:
                svc["cves"] = self.lookup_cves(
                    svc.get("service", ""), svc.get("version", "unknown")
                )
            except Exception:
                svc["cves"] = []

        return services

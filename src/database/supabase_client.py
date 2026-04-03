import json
import os
import logging
from datetime import datetime, timezone
from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions

logger = logging.getLogger(__name__)

def _get_client() -> Client:
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    # Use Service Role Key for backend workers to bypass RLS
    SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY")

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in environment variables"
        )

    return create_client(
        SUPABASE_URL,
        SUPABASE_KEY,
        options=SyncClientOptions(postgrest_client_timeout=30),
    )


def _insert_scan_row(client: Client, row: dict) -> dict:
    try:
        response = client.table("scans").insert(row).execute()
        return response.data[0]
    except Exception as first_error:
        if "ports_count" not in row:
            raise

        error_message = str(first_error).lower()
        if "ports_count" not in error_message and "column" not in error_message:
            raise

        fallback_row = dict(row)
        fallback_row.pop("ports_count", None)
        logger.warning(f"[Supabase] Retrying scan insert without ports_count: {first_error}")
        response = client.table("scans").insert(fallback_row).execute()
        return response.data[0]

def store_scan_result(
    user_id: str,
    target_redacted: str,
    ports: list,
    cve_findings: list,
    ai_summary: str,
    scan_mode="fast"
) -> dict:
    ports_count = len(ports or [])
    highest_cvss = 0.0
    crit_count = high_count = med_count = low_count = 0

    # Pre-calculate severity distribution for the ultra-fast frontend chart
    for cve in cve_findings:
        try:
            cvss = float(cve.get("cvss", 0))
            if cvss > highest_cvss:
                highest_cvss = cvss
            
            if cvss >= 9.0: crit_count += 1
            elif cvss >= 7.0: high_count += 1
            elif cvss >= 4.0: med_count += 1
            elif cvss > 0: low_count += 1
        except (ValueError, TypeError):
            pass

    row = {
        "user_id": user_id,
        "target_redacted": target_redacted,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "ports_count": ports_count,
        "ports_json": json.dumps(ports),
        "cve_findings_json": json.dumps(cve_findings),
        "ai_summary": ai_summary,
        "scan_mode": scan_mode if scan_mode else "fast",
        "cve_count": len(cve_findings),
        "highest_cvss": highest_cvss,
        "crit_count": crit_count,
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
    }

    return _insert_scan_row(_get_client(), row)


def get_user_scans(user_id: str) -> list[dict]:
    return (
        _get_client()
        .table("scans")
        .select("*")
        .eq("user_id", user_id)
        .order("scan_timestamp", desc=True)
        .limit(10)
        .execute()
        .data
    )

def get_global_cached_report(signature: str) -> str:
    """Pulls a cached AI report from the global Supabase hive mind."""
    try:
        client = _get_client() # <-- Changed to match your existing function
        response = client.table("global_ai_cache").select("report_text").eq("signature", signature).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]["report_text"]
        return None
    except Exception as e:
        logger.warning(f"[Supabase] Global cache read failed: {e}")
        return None

def store_global_cached_report(signature: str, report_text: str):
    """Pushes a newly generated AI report to the global cache for other users."""
    try:
        client = _get_client() # <-- Changed to match your existing function
        client.table("global_ai_cache").insert({
            "signature": signature,
            "report_text": report_text
        }).execute()
        logger.info(f"[Supabase] Successfully pushed report to global cache")
    except Exception as e:
        # If it fails (e.g., someone else inserted it at the exact same time), it's fine.
        logger.warning(f"[Supabase] Global cache write skipped/failed: {e}")
import json
import os
import logging
from datetime import datetime, timezone
from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions

logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise ValueError(
        "SUPABASE_URL and SUPABASE_ANON_KEY must be set in environment variables"
    )


def _get_client() -> Client:
    return create_client(
        SUPABASE_URL,
        SUPABASE_ANON_KEY,
        options=SyncClientOptions(postgrest_client_timeout=30),
    )


supabase: Client | None = None


def store_scan_result(
    user_id: str,
    target_redacted: str,
    ports: list,
    cve_findings: list,
    ai_summary: str,
) -> dict:
    highest_cvss = 0.0
    for cve in cve_findings:
        try:
            cvss = float(cve.get("cvss", 0))
            if cvss > highest_cvss:
                highest_cvss = cvss
        except (ValueError, TypeError):
            pass

    row = {
        "user_id": user_id,
        "target_redacted": target_redacted,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "ports_json": json.dumps(ports),
        "cve_findings_json": json.dumps(cve_findings),
        "ai_summary": ai_summary,
        "cve_count": len(cve_findings),
        "highest_cvss": highest_cvss,
    }

    return _get_client().table("scans").insert(row).execute().data[0]


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
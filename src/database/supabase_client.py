import json
import os
from datetime import datetime, timezone
from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions

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

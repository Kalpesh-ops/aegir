import logging
from datetime import datetime, timezone
from src.database.supabase_client import _get_client

logger = logging.getLogger(__name__)

CURRENT_POLICY_VERSION = "1.0"


def get_consent(user_id: str) -> dict | None:
    """Returns consent row for user, or None if not found."""
    try:
        res = _get_client().table("user_consent").select("*").eq("user_id", user_id).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        logger.error(f"[Consent] Failed to fetch consent for {user_id}: {e}")
        return None


def has_valid_consent(user_id: str) -> bool:
    """True if user has active, non-revoked consent on current policy version."""
    record = get_consent(user_id)
    if not record:
        return False
    if not record.get("consented"):
        return False
    if record.get("revoked_at"):
        return False
    return record.get("policy_version") == CURRENT_POLICY_VERSION


def save_consent(user_id: str, client_ip: str, app_version: str) -> dict:
    """Upsert consent record when user explicitly accepts."""
    row = {
        "user_id": user_id,
        "consented": True,
        "consented_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": CURRENT_POLICY_VERSION,
        "consent_method": "explicit_checkbox",
        "ip_address": client_ip,
        "app_version": app_version,
        "revoked_at": None,
        "revoked_reason": None,
    }
    try:
        _get_client().table("user_consent").upsert(row).execute()
        logger.info(f"[Consent] Saved for user {user_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"[Consent] Failed to save consent for {user_id}: {e}")
        raise


def revoke_consent(user_id: str, reason: str = "user_requested") -> dict:
    """Mark consent as revoked."""
    try:
        _get_client().table("user_consent").update({
            "consented": False,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "revoked_reason": reason,
        }).eq("user_id", user_id).execute()
        logger.info(f"[Consent] Revoked for user {user_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"[Consent] Failed to revoke consent for {user_id}: {e}")
        raise

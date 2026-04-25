"""
NetSec AI Scanner — FastAPI backend.

Designed to run **locally** alongside the frontend (Electron / desktop exe).
The HTTP listener binds to ``127.0.0.1`` by default and ``TrustedHostMiddleware``
blocks non-loopback ``Host`` headers so DNS-rebinding attacks cannot pivot
through it from a browser tab the user happens to have open.
"""

import sys
import os
import threading
import time
import uuid
from enum import Enum
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import logging

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.scanner.tshark_engine import TSharkScanner
from src.ai_agent.gemini_client import GeminiAgent
from src.vuln_lookup.circl_client import CIRCLClient
from src.utils.data_sanitizer import sanitize_scan_data  # noqa: F401  (public API)
from src.utils.token_optimizer import prune_scan_data
from src.utils.log_scrubber import install_scrubber
from src.utils.validators import TargetValidationError, validate_target
from src.queue.job_manager import clear_user_jobs, create_job, get_job_status
from src.auth.middleware import get_current_user
from src.database.supabase_client import (
    delete_user_account_data,
    delete_user_scans as supabase_delete_user_scans,
    get_user_scans,
)
from src.database.consent_manager import has_valid_consent, revoke_consent, save_consent
from src.dependencies import detector as dep_detector
from src.dependencies import installer as dep_installer
from src.dependencies import registry as dep_registry


# --- Logging ----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
install_scrubber()

# --- Rate limiting (local-first, in-memory sliding window) ------------------
# For a single-user Electron deployment we are not defending against
# distributed abuse — these limits mainly catch accidental loops (e.g. a buggy
# UI poll) and protect the Gemini quota. Authenticated routes are keyed by
# ``user_id``; unauthenticated ones by ``client.host`` (with the caveat that
# behind a reverse proxy every user shares a bucket, which is an acceptable
# trade-off here).
_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(key: str, max_calls: int, window_seconds: float) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_buckets[key] = [t for t in _rate_buckets[key] if now - t < window_seconds]
        if len(_rate_buckets[key]) >= max_calls:
            return False
        _rate_buckets[key].append(now)
        return True


# --- App + middleware -------------------------------------------------------
app = FastAPI(title="NetSec AI Kernel")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Attach a restrictive set of response headers.

    The CSP is safe for the API response shape (JSON / plain text) and for the
    swagger UI served by FastAPI at ``/docs``. The Electron renderer sets its
    own, stricter CSP at the document level — these headers are defence-in-
    depth when the backend is reached via a browser tab directly.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        # Only emit HSTS when served over HTTPS; on 127.0.0.1 it's pointless
        # and confuses some browsers into pinning a loopback hostname.
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a per-request UUID for correlation between server logs and 500s."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# CORS: default to the Electron renderer's origin (``app://`` or ``file://``)
# plus localhost dev servers. Extra allowed origins may be appended via the
# ``EXTRA_CORS_ORIGINS`` env var (comma-separated) for e.g. a hosted staging
# deploy.
DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "https://netsec-ai-scanner.vercel.app",
]
extra_origins = [
    o.strip()
    for o in os.getenv("EXTRA_CORS_ORIGINS", "").split(",")
    if o.strip()
]
CORS_ORIGINS = DEFAULT_CORS_ORIGINS + extra_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

ALLOWED_HOSTS = [
    h.strip()
    for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    logging.error(
        f"Unhandled exception on {request.method} {request.url.path} (rid={rid}): {exc}"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred.",
            "request_id": rid,
        },
    )


# --- Engines (lazy singletons) ----------------------------------------------
nmap_engine = NmapScanner()
scapy_engine = ScapyEngine()
tshark_engine = TSharkScanner()
ai_agent = GeminiAgent()
circl_client = CIRCLClient()
logging.info(f"CIRCL API reachable: {circl_client.test_connection()}")


class ScanMode(str, Enum):
    fast = "fast"
    deep = "deep"
    pen_test = "pen_test"


SCAN_PROFILES = {
    "fast": {
        "label": "Fast Scan",
        "estimated_seconds": {"nmap": 30, "scapy": 0, "tshark": 0, "ai": 8, "total": 38},
    },
    "deep": {
        "label": "Deep Scan",
        "estimated_seconds": {"nmap": 90, "scapy": 3, "tshark": 0, "ai": 12, "total": 105},
    },
    "pen_test": {
        "label": "Pen Testing Scan",
        "estimated_seconds": {"nmap": 180, "scapy": 5, "tshark": 25, "ai": 15, "total": 225},
    },
}


# --- Request models ---------------------------------------------------------
class ScanRequest(BaseModel):
    target: str
    scan_mode: ScanMode = ScanMode.fast
    use_xml: bool = False


class ScanQueueRequest(BaseModel):
    target: str
    scan_mode: ScanMode = ScanMode.fast
    scan_type: ScanMode | None = None


class ConsentRequest(BaseModel):
    app_version: str = "1.0"


class AnalyzeRequest(BaseModel):
    open_ports: list = []
    cve_findings: list = []


class APIKeyRequest(BaseModel):
    api_key: str


class LicenseAcceptRequest(BaseModel):
    dep_id: str


class InstallRequest(BaseModel):
    dep_id: str


# --- Routes -----------------------------------------------------------------
@app.post("/api/scan")
async def run_scan(
    request: Request,
    body: ScanQueueRequest,
    user_id: str = Depends(get_current_user),
):
    """Queue a scan job for async processing by the background worker."""
    if not _check_rate_limit(f"scan:{user_id}", max_calls=5, window_seconds=3600):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    try:
        validate_target(body.target)
    except TargetValidationError as ve:
        logging.info(f"[!] Target validation rejection: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        rid = getattr(request.state, "request_id", "-")
        logging.error(f"[!] Unexpected validation error (rid={rid}): {e}")
        raise HTTPException(status_code=500, detail="Internal error")

    try:
        requested_mode = body.scan_mode
        if "scan_mode" not in body.model_fields_set and body.scan_type is not None:
            requested_mode = body.scan_type
        job_id = create_job(user_id, body.target, requested_mode.value)
        logging.info(f"[*] Scan queued: job={job_id} mode={requested_mode.value}")
        return {"scan_id": job_id, "status": "queued", "message": "Scan queued successfully"}
    except Exception as e:
        rid = getattr(request.state, "request_id", "-")
        logging.error(f"[!] Queue error (rid={rid}): {e}")
        raise HTTPException(status_code=500, detail="Failed to queue scan")


@app.get("/api/scan/{scan_id}")
async def get_scan_status(
    request: Request, scan_id: str, user_id: str = Depends(get_current_user)
):
    """Retrieve the status and result of a queued scan job."""
    if not _check_rate_limit(f"status:{user_id}", max_calls=120, window_seconds=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    result = get_job_status(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if result.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return result


@app.get("/api/scans")
async def list_user_scans(user_id: str = Depends(get_current_user)):
    """Return the last 10 scans for the authenticated user."""
    return get_user_scans(user_id)


@app.delete("/api/scans")
async def delete_user_scans_route(user_id: str = Depends(get_current_user)):
    """
    Clear scan history for the authenticated user, locally **and** in Supabase.
    Previously this only cleared the local SQLite queue (M-5).
    """
    deleted_supabase = 0
    try:
        deleted_supabase = supabase_delete_user_scans(user_id)
    except Exception as e:
        logging.error(f"[!] Supabase delete error: {e}")
    try:
        clear_user_jobs(user_id)
    except Exception as e:
        logging.error(f"[!] Local delete error: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear local history")

    return {
        "status": "success",
        "message": "Scan history cleared",
        "deleted_supabase_rows": deleted_supabase,
    }


@app.delete("/api/account")
async def delete_account(user_id: str = Depends(get_current_user)):
    """GDPR-style erasure: purge every row owned by the current user."""
    try:
        summary = delete_user_account_data(user_id)
        clear_user_jobs(user_id)
        return {"status": "success", **summary}
    except Exception as e:
        logging.error(f"[!] Account deletion error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account data")


@app.get("/api/consent")
async def check_consent(user_id: str = Depends(get_current_user)):
    return {"has_consent": has_valid_consent(user_id)}


@app.post("/api/consent")
async def grant_consent(
    request: Request,
    body: ConsentRequest,
    user_id: str = Depends(get_current_user),
):
    client_ip = request.client.host if request.client else "unknown"
    save_consent(user_id, client_ip, body.app_version)
    return {"success": True}


@app.delete("/api/consent")
async def revoke_user_consent(user_id: str = Depends(get_current_user)):
    revoke_consent(user_id)
    return {"success": True}


@app.post("/api/analyze")
async def analyze_scan(
    request: Request,
    body: AnalyzeRequest,
    user_id: str = Depends(get_current_user),
):
    """
    On-demand AI analysis over an already-collected port/CVE profile.

    Authenticated (C-2) and per-user rate-limited so the shared Gemini key
    cannot be exhausted by anonymous callers.
    """
    if not _check_rate_limit(f"analyze:{user_id}", max_calls=10, window_seconds=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    try:
        logging.info("[*] Received analysis request")
        optimized_data = prune_scan_data(
            {"open_ports": body.open_ports, "cve_findings": body.cve_findings}
        )
        ports = optimized_data.get("open_ports", [])
        cve_findings = optimized_data.get("cve_findings", [])
        logging.info("[*] Sending optimized data to Gemini...")
        report = ai_agent.analyze_scan(ports, cve_findings)
        logging.info("[✓] AI analysis complete")
        return {"report": report}
    except HTTPException:
        raise
    except Exception as e:
        rid = getattr(request.state, "request_id", "-")
        logging.error(f"[!] Analysis error (rid={rid}): {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@app.post("/api/settings/apikey")
async def update_api_key(
    request: Request,
    body: APIKeyRequest,
    user_id: str = Depends(get_current_user),
):
    """
    Save the BYOK Gemini key. Authenticated (C-1), rate-limited, and stored
    encrypted at rest via :mod:`src.utils.secrets`.
    """
    if not _check_rate_limit(f"apikey:{user_id}", max_calls=5, window_seconds=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    success = ai_agent.save_user_api_key(body.api_key)
    if success:
        return {"status": "success", "message": "API Key saved securely."}
    return JSONResponse(
        status_code=400,
        content={"status": "error", "message": "Failed to save API Key."},
    )


@app.get("/api/setup/detect")
async def setup_detect(user_id: str = Depends(get_current_user)):
    """List every native dependency the scanner can drive, with live install status.

    The wizard polls this on render. Result is cached for a few seconds in
    :mod:`src.dependencies.detector` so polling is cheap.
    """
    return {"dependencies": dep_detector.public_status()}


@app.post("/api/setup/license")
async def setup_accept_license(
    body: LicenseAcceptRequest,
    user_id: str = Depends(get_current_user),
):
    """Persist the user's acknowledgement of an upstream license URL.

    Required before ``/api/setup/install`` will queue a job for that dep.
    """
    spec = dep_registry.get_dependency(body.dep_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Unknown dependency.")
    license_url = spec.get("license_url")
    if not license_url:
        # Nothing to accept; treat as a no-op success so the UI flow is uniform.
        return {"status": "ok", "accepted": False}
    dep_installer.record_license_acceptance(
        body.dep_id, license_url, user_id=user_id
    )
    return {"status": "ok", "accepted": True}


@app.post("/api/setup/install")
async def setup_install(
    request: Request,
    body: InstallRequest,
    user_id: str = Depends(get_current_user),
):
    """Queue an upstream-installer download + execute job for one dep."""
    if not _check_rate_limit(f"setup-install:{user_id}", max_calls=10, window_seconds=600):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many install requests"},
        )
    try:
        job = dep_installer.queue_install(body.dep_id, user_id=user_id)
    except PermissionError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"job": job.to_dict()}


@app.get("/api/setup/install/{job_id}")
async def setup_install_status(
    job_id: str,
    user_id: str = Depends(get_current_user),
):
    job = dep_installer.status(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown install job.")
    return {"job": job.to_dict()}


@app.post("/api/setup/install/{job_id}/cancel")
async def setup_install_cancel(
    job_id: str,
    user_id: str = Depends(get_current_user),
):
    if not dep_installer.cancel(job_id):
        raise HTTPException(status_code=404, detail="Job not cancellable.")
    return {"status": "cancelling"}


@app.get("/api/setup/jobs")
async def setup_install_list(user_id: str = Depends(get_current_user)):
    return {"jobs": dep_installer.all_statuses()}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "backend": "online", "version": "2.1"}


if __name__ == "__main__":
    import uvicorn
    from src.queue.worker import run_worker

    if sys.stdout is None or sys.stderr is None:
        log_file = open("netsec-backend.log", "a")
        sys.stdout = log_file
        sys.stderr = log_file

    threading.Thread(target=run_worker, daemon=True).start()

    # Bind strictly to loopback. For advanced deployments an operator can set
    # ``NETSEC_BIND_HOST`` explicitly — but ``0.0.0.0`` should never be the
    # default for a local-first app (H-5).
    bind_host = os.getenv("NETSEC_BIND_HOST", "127.0.0.1")
    bind_port = int(os.getenv("NETSEC_BIND_PORT", "8000"))
    logging.info(f"[*] Starting NetSec AI Kernel on http://{bind_host}:{bind_port}")
    uvicorn.run(app, host=bind_host, port=bind_port, reload=False)

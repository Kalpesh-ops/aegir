import sys
import os
import re
import ipaddress
import threading
import time
from enum import Enum
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import logging

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.scanner.tshark_engine import TSharkScanner
from src.ai_agent.gemini_client import GeminiAgent
from src.vuln_lookup.circl_client import CIRCLClient
from src.utils.data_sanitizer import sanitize_scan_data
from src.utils.token_optimizer import prune_scan_data
from src.queue.job_manager import create_job, get_job_status
from src.auth.middleware import get_current_user
from src.database.supabase_client import get_user_scans

# --- Simple in-memory rate limiters ---
_scan_rate_lock = threading.Lock()
_scan_rate: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(key: str, max_calls: int, window_seconds: float) -> bool:
    """Return True if the request is within the rate limit, False if exceeded."""
    now = time.time()
    with _scan_rate_lock:
        _scan_rate[key] = [t for t in _scan_rate[key] if now - t < window_seconds]
        if len(_scan_rate[key]) >= max_calls:
            return False
        _scan_rate[key].append(now)
        return True


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

app = FastAPI(title="NetSec AI Kernel")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://netsec-ai-scanner.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logging.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred.",
        },
    )


# Initialize engines
nmap_engine = NmapScanner()
scapy_engine = ScapyEngine()
tshark_engine = TSharkScanner()
ai_agent = GeminiAgent()
circl_client = CIRCLClient()
logging.info(f"CIRCL API reachable: {circl_client.test_connection()}")


# --- ENUMS ---
class ScanMode(str, Enum):
    fast = "fast"
    deep = "deep"
    pen_test = "pen_test"


# --- SCAN PROFILES ---
SCAN_PROFILES = {
    "fast": {
        "label": "Fast Scan",
        "estimated_seconds": {
            "nmap": 30,
            "scapy": 0,
            "tshark": 0,
            "ai": 8,
            "total": 38,
        },
    },
    "deep": {
        "label": "Deep Scan",
        "estimated_seconds": {
            "nmap": 90,
            "scapy": 3,
            "tshark": 0,
            "ai": 12,
            "total": 105,
        },
    },
    "pen_test": {
        "label": "Pen Testing Scan",
        "estimated_seconds": {
            "nmap": 180,
            "scapy": 5,
            "tshark": 25,
            "ai": 15,
            "total": 225,
        },
    },
}


# --- SECURITY: INPUT VALIDATION ---
def validate_target(target: str):
    ipv4_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    cidr_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])$"

    if target == "localhost":
        return True

    if re.match(cidr_regex, target):
        net = ipaddress.ip_network(target, strict=False)
        if not net.is_private and not net.is_loopback:
            raise ValueError(
                "Public IP ranges are not permitted. Only private or loopback ranges allowed."
            )
        if net.prefixlen > 24:
            raise ValueError(
                "CIDR prefix must be /24 or smaller (more specific networks not allowed)."
            )
        return True

    if re.match(ipv4_regex, target):
        addr = ipaddress.ip_address(target)
        if not addr.is_private and not addr.is_loopback and not addr.is_reserved:
            raise ValueError(
                "Public IPs are not permitted. Only private or loopback addresses allowed."
            )
        return True

    if re.match(domain_regex, target):
        return True

    raise ValueError("Invalid Target Format. Detection of potential injection attack.")


class ScanRequest(BaseModel):
    target: str
    scan_mode: ScanMode = ScanMode.fast
    use_xml: bool = False  # Use XML-based scanning (more reliable in some environments)


class ScanQueueRequest(BaseModel):
    target: str


# --- FIREWALL ANALYSIS HELPERS ---


def infer_firewall_from_nmap(scan_data: dict, target: str) -> dict:
    """
    Fallback firewall detection using Nmap port state analysis.

    Logic:
    - If ANY port is 'filtered' -> Stateful firewall detected
    - If ports are 'closed' but host is up -> Likely unfiltered/stateless
    - If ALL ports are 'open' -> Very permissive firewall
    - Mixed states -> Complex firewall rules

    Args:
        scan_data: Raw Nmap scan result dict
        target: Target IP for reference

    Returns:
        dict with firewall_status, explanation, and inference_method
    """
    try:
        hosts = scan_data.get("hosts", [])
        if not hosts:
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Host Data",
                "firewall_status": "Unknown",
                "explanation": "No host data available from Nmap scan.",
                "inference_method": "nmap_fallback",
                "confidence": "low",
            }

        host_data = hosts[0]
        open_ports = host_data.get("open_ports", [])

        if not open_ports:
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Open Ports",
                "firewall_status": "Highly Restrictive / Firewall Active",
                "explanation": "No open ports detected. Target is either offline or protected by an aggressive firewall.",
                "inference_method": "nmap_fallback",
                "confidence": "high",
            }

        # Analyze port states
        port_states = {}
        for port in open_ports:
            state = (
                port.get("state", "unknown") if isinstance(port, dict) else "unknown"
            )
            port_states[state] = port_states.get(state, 0) + 1

        total_ports = len(open_ports)
        if total_ports == 0:
            # Safety check - shouldn't reach here due to earlier check, but just in case
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Data",
                "firewall_status": "Unable to Determine",
                "explanation": "No port data available for analysis.",
                "inference_method": "nmap_fallback",
                "confidence": "low",
            }

        filtered_count = port_states.get("filtered", 0)
        open_count = port_states.get("open", 0)
        closed_count = port_states.get("closed", 0)

        logging.info(f"[Firewall Inference] Port states: {port_states}")

        # --- INFERENCE RULES ---

        # Rule 1: High percentage of filtered ports = Stateful Firewall
        if filtered_count > 0 and (filtered_count / len(open_ports)) >= 0.5:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Filtered Majority)",
                "firewall_status": "Stateful / Filtered (Inferred via Nmap)",
                "explanation": f"Nmap detected {filtered_count}/{len(open_ports)} ports as filtered. This indicates a stateful firewall is active, blocking unsolicited packets.",
                "inference_method": "nmap_fallback",
                "confidence": "high",
                "port_breakdown": port_states,
            }

        # Rule 2: Mostly open ports with some filtered = Complex Rules
        if open_count > 0 and filtered_count > 0:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Open + Filtered)",
                "firewall_status": "Stateful with Selective Rules (Inferred via Nmap)",
                "explanation": f"Nmap detected {open_count} open and {filtered_count} filtered ports. The firewall has selective rules allowing some services.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states,
            }

        # Rule 3: All or mostly open = Permissive Firewall
        if open_count >= (len(open_ports) - 1):
            return {
                "target": target,
                "port": "multiple",
                "response_type": "All Open",
                "firewall_status": "Permissive / Unfiltered (Inferred via Nmap)",
                "explanation": f"Nmap detected {open_count}/{len(open_ports)} ports as open with minimal filtering. Firewall is permissive or absent.",
                "inference_method": "nmap_fallback",
                "confidence": "high",
                "port_breakdown": port_states,
            }

        # Rule 4: Mix of closed and filtered = Moderate Security
        if closed_count > 0 and filtered_count > 0:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Closed + Filtered)",
                "firewall_status": "Moderate Firewall (Stateless Likely)",
                "explanation": f"Nmap detected closed and filtered ports. Firewall likely responds differently to various probes.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states,
            }

        # Rule 5: Mostly closed ports = Stateless/Unfiltered
        if closed_count >= (len(open_ports) - 1):
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mostly Closed",
                "firewall_status": "Stateless / Unfiltered (Inferred via Nmap)",
                "explanation": "Most ports are closed (host responds), suggesting a stateless firewall or host-level filtering.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states,
            }

        # Default fallback
        return {
            "target": target,
            "port": "multiple",
            "response_type": "Indeterminate",
            "firewall_status": "Unknown Firewall State (Inferred via Nmap)",
            "explanation": "Nmap detected mixed port states. Firewall configuration is complex or indeterminate.",
            "inference_method": "nmap_fallback",
            "confidence": "low",
            "port_breakdown": port_states,
        }

    except Exception as e:
        logging.error(f"Nmap firewall inference failed: {e}")
        return {
            "target": target,
            "port": "N/A",
            "response_type": "Inference Error",
            "firewall_status": "Unable to Determine",
            "explanation": f"Firewall inference failed: {str(e)}",
            "inference_method": "nmap_fallback",
            "confidence": "low",
        }


def analyze_firewall(scan_data: dict, target: str, scan_mode: str) -> dict:
    """
    Primary firewall analysis with graceful fallback.

    Strategy:
    1. Try Scapy direct probe (requires admin/root)
    2. Fall back to Nmap inference if Scapy fails

    Args:
        scan_data: Raw Nmap result
        target: Target IP
        scan_mode: Scan mode (determines whether to attempt Scapy)

    Returns:
        dict with firewall analysis (from Scapy or Nmap inference)
    """
    # Only attempt Scapy on deep/pen_test modes
    if scan_mode not in ["deep", "pen_test"]:
        return {
            "status": "skipped",
            "reason": f"Firewall analysis not enabled for {scan_mode} mode",
        }

    logging.info(f"[Firewall Analysis] Attempting Scapy probe on {target}...")

    try:
        # Determine target port based on scan mode
        firewall_port = 445 if scan_mode == "pen_test" else 80

        # Attempt direct probe with Scapy
        fw_status = scapy_engine.firewall_detect(target, port=firewall_port)

        # Check if Scapy encountered an error
        if "error" in fw_status:
            raise PermissionError(fw_status["error"])

        logging.info(
            f"[Firewall Analysis] Scapy probe successful: {fw_status['firewall_status']}"
        )
        fw_status["inference_method"] = "scapy_direct"
        return fw_status

    except PermissionError as pe:
        logging.warning(f"[Firewall Analysis] Scapy requires elevated privileges: {pe}")
        logging.info(f"[Firewall Analysis] Falling back to Nmap-based inference...")

        # Use Nmap inference as fallback
        return infer_firewall_from_nmap(scan_data, target)

    except Exception as e:
        logging.warning(
            f"[Firewall Analysis] Scapy probe failed ({type(e).__name__}): {e}"
        )
        logging.info(f"[Firewall Analysis] Falling back to Nmap-based inference...")

        # Use Nmap inference as fallback
        return infer_firewall_from_nmap(scan_data, target)


@app.post("/api/scan")
async def run_scan(
    request: Request, body: ScanQueueRequest, user_id: str = Depends(get_current_user)
):
    """
    Queue a network scan job for async processing by the background worker.

    Args:
        request: ScanQueueRequest with target.

    Returns:
        {"scan_id": job_id, "status": "queued", "message": "..."}
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"scan:{client_ip}", max_calls=5, window_seconds=3600):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    try:
        validate_target(body.target)
        job_id = create_job(user_id, body.target)
        logging.info(f"[*] Scan queued: job={job_id} target={body.target}")
        return {
            "scan_id": job_id,
            "status": "queued",
            "message": "Scan queued successfully",
        }
    except ValueError as ve:
        logging.error(f"[!] Validation error: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logging.error(f"[!] Queue error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}")
async def get_scan_status(
    request: Request, scan_id: str, user_id: str = Depends(get_current_user)
):
    """Retrieve the status and result of a queued scan job."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"status:{client_ip}", max_calls=60, window_seconds=60):
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


@app.post("/api/analyze")
async def analyze_scan(request: Request, data: dict):
    """AI threat analysis endpoint."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"analyze:{client_ip}", max_calls=10, window_seconds=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "detail": "Too many requests"},
        )
    try:
        logging.info(f"[*] Received analysis request")
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="Invalid request body")
        optimized_data = prune_scan_data(data)
        ports = optimized_data.get("open_ports", [])
        cve_findings = optimized_data.get("cve_findings", [])
        if not isinstance(ports, list) or not isinstance(cve_findings, list):
            raise HTTPException(status_code=400, detail="Invalid data format")
        logging.info(f"[*] Sending optimized data to Gemini...")
        report = ai_agent.analyze_scan(ports, cve_findings)
        logging.info(f"[✓] AI analysis complete")
        return {"report": report}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[!] Analysis error: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "backend": "online", "version": "2.0"}


if __name__ == "__main__":
    import uvicorn
    from src.queue.worker import run_worker

    threading.Thread(target=run_worker, daemon=True).start()
    logging.info("[*] Starting NetSec AI Kernel on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)

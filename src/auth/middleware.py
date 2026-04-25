"""
Supabase JWT verification middleware for FastAPI.

Verifies ES256-signed tokens against the project's JWKS endpoint. The correct
key is selected by the token's ``kid`` header so Supabase key rotation does not
break existing sessions.

``audience`` and ``issuer`` are both enforced. They can be overridden via the
``SUPABASE_JWT_AUDIENCE`` / ``SUPABASE_JWT_ISSUER`` environment variables in
case a non-default Supabase configuration is in use.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from threading import Lock

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

def _require_supabase_url() -> str:
    """
    Resolve ``SUPABASE_URL`` at use-time rather than import-time.

    Previously this module silently defaulted to a specific Supabase project
    when the env var was missing, which meant any install without a configured
    ``SUPABASE_URL`` would happily accept JWTs from an unrelated tenant
    (audit finding C-3). The default is now removed and we raise at the first
    point that actually needs the URL — module imports (including tests) still
    work with the env var unset.
    """
    raw = os.getenv("SUPABASE_URL")
    if not raw:
        raise RuntimeError(
            "SUPABASE_URL environment variable is required for JWT verification. "
            "Set it to your Supabase project URL (e.g. https://abcd.supabase.co) "
            "before starting the backend."
        )
    return raw.rstrip("/")


SUPABASE_JWT_AUDIENCE = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")


def _supabase_jwks_url() -> str:
    return f"{_require_supabase_url()}/auth/v1/.well-known/jwks.json"


def _supabase_jwt_issuer() -> str:
    return os.getenv("SUPABASE_JWT_ISSUER") or f"{_require_supabase_url()}/auth/v1"

_JWKS_CACHE: dict | None = None
_JWKS_FETCHED_AT: float = 0.0
_JWKS_CACHE_TTL: float = 3600.0
_JWKS_LOCK = Lock()


def _fetch_jwks(force: bool = False) -> dict:
    global _JWKS_CACHE, _JWKS_FETCHED_AT
    now = time.time()
    with _JWKS_LOCK:
        if (
            not force
            and _JWKS_CACHE is not None
            and (now - _JWKS_FETCHED_AT) < _JWKS_CACHE_TTL
        ):
            return _JWKS_CACHE
        resp = requests.get(_supabase_jwks_url(), timeout=10)
        resp.raise_for_status()
        _JWKS_CACHE = resp.json()
        _JWKS_FETCHED_AT = now
        return _JWKS_CACHE


def _jwk_to_pem(jwk: dict) -> bytes:
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1(),
    )
    public_key = public_numbers.public_key(default_backend())
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _select_jwk(kid: str | None) -> dict:
    """Find the JWK matching ``kid``, refreshing the cache once on miss."""
    for force in (False, True):
        jwks = _fetch_jwks(force=force)
        keys = jwks.get("keys", [])
        if not keys:
            continue
        if kid is None:
            return keys[0]
        for key in keys:
            if key.get("kid") == kid:
                return key
    raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authentication required")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    token = parts[1]
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    kid = unverified_header.get("kid")
    jwk = _select_jwk(kid)
    public_key = _jwk_to_pem(jwk)

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            audience=SUPABASE_JWT_AUDIENCE,
            issuer=_supabase_jwt_issuer(),
            options={"require": ["exp", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user_id

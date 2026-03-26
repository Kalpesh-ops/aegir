import os
import base64
import requests
import time
from functools import lru_cache
from fastapi import Request, HTTPException
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt

SUPABASE_JWKS_URL = (
    "https://jehssaanufkgidltbwtp.supabase.co/auth/v1/.well-known/jwks.json"
)
_JWKS_CACHE: dict | None = None
_JWKS_FETCHED_AT: float = 0
_JWKS_CACHE_TTL: float = 3600


def _fetch_jwks(force: bool = False) -> dict:
    global _JWKS_CACHE, _JWKS_FETCHED_AT
    now = time.time()
    if (
        not force
        and _JWKS_CACHE is not None
        and (now - _JWKS_FETCHED_AT) < _JWKS_CACHE_TTL
    ):
        return _JWKS_CACHE
    resp = requests.get(SUPABASE_JWKS_URL, timeout=10)
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


@lru_cache(maxsize=1)
def _get_public_key() -> bytes:
    jwks = _fetch_jwks()
    keys = jwks.get("keys", [])
    if not keys:
        raise RuntimeError("No keys found in Supabase JWKS")
    return _jwk_to_pem(keys[0])


def get_current_user(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authentication required")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    token = parts[1]
    try:
        public_key = _get_public_key()
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            options={
                "verify_sub": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user_id

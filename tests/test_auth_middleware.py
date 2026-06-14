"""JWT verification in src.auth.middleware.get_current_user.

Uses a real EC P-256 keypair: tokens are genuinely signed and genuinely
verified. Only the JWKS network fetch is mocked.
"""

from __future__ import annotations

import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from src.auth import middleware

ISSUER = "https://example.supabase.co/auth/v1"
KID = "test-key-1"


def _b64url(n: int) -> str:
    raw = n.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def signing_setup(monkeypatch):
    """Generate a keypair, publish its JWK, and pin issuer/audience."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.public_key().public_numbers()
    jwk = {"kid": KID, "kty": "EC", "crv": "P-256", "x": _b64url(nums.x), "y": _b64url(nums.y)}

    monkeypatch.setattr(middleware, "_fetch_jwks", lambda force=False: {"keys": [jwk]})
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(middleware, "SUPABASE_JWT_AUDIENCE", "authenticated")
    return private_key


def _make_token(private_key, *, kid=KID, audience="authenticated", issuer=ISSUER,
                sub="user-123", exp_offset=3600, algorithm="ES256"):
    payload = {"sub": sub, "aud": audience, "iss": issuer, "exp": int(time.time()) + exp_offset}
    return jwt.encode(payload, private_key, algorithm=algorithm, headers={"kid": kid})


class _Req:
    """Minimal stand-in for starlette Request (only .headers is used)."""

    def __init__(self, auth=None):
        self.headers = {"Authorization": auth} if auth else {}


def test_valid_token_returns_sub(signing_setup):
    token = _make_token(signing_setup)
    assert middleware.get_current_user(_Req(f"Bearer {token}")) == "user-123"


def test_missing_header_rejected(signing_setup):
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req())
    assert exc.value.status_code == 401


def test_non_bearer_scheme_rejected(signing_setup):
    token = _make_token(signing_setup)
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Basic {token}"))
    assert exc.value.status_code == 401


def test_expired_token_rejected(signing_setup):
    token = _make_token(signing_setup, exp_offset=-10)
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Bearer {token}"))
    assert exc.value.status_code == 401


def test_wrong_audience_rejected(signing_setup):
    token = _make_token(signing_setup, audience="some-other-service")
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Bearer {token}"))
    assert exc.value.status_code == 401


def test_wrong_issuer_rejected(signing_setup):
    token = _make_token(signing_setup, issuer="https://evil.supabase.co/auth/v1")
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Bearer {token}"))
    assert exc.value.status_code == 401


def test_signature_from_other_key_rejected(signing_setup):
    """A token signed by a different key must fail verification."""
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    token = _make_token(attacker_key)  # published JWK is for signing_setup's key
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Bearer {token}"))
    assert exc.value.status_code == 401


def test_unknown_kid_rejected(signing_setup):
    token = _make_token(signing_setup, kid="no-such-kid")
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req(f"Bearer {token}"))
    assert exc.value.status_code == 401


def test_malformed_token_rejected(signing_setup):
    with pytest.raises(HTTPException) as exc:
        middleware.get_current_user(_Req("Bearer not.a.jwt"))
    assert exc.value.status_code == 401

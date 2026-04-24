"""
Per-install symmetric encryption for secrets stored at rest (e.g. BYOK Gemini key).

This module maintains a Fernet key in ``data/.install_key`` with restrictive
file-system permissions (600 on POSIX). The key is generated the first time it
is needed and reused thereafter.

The encryption is intentionally transparent to the application: all callers see
plaintext strings. It is **not** a substitute for a proper secrets manager —
anyone with read access to the ``data/`` directory can recover the secret. The
goal is defence-in-depth against casual filesystem exposure (backups, log
scrapers, accidental repo commits), not against a privileged local attacker.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from threading import Lock

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_KEY_PATH = _DATA_DIR / ".install_key"

_fernet: Fernet | None = None
_lock = Lock()


def _load_or_create_key() -> bytes:
    """Return the Fernet key, creating one on first use."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes().strip()

    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)
    try:
        os.chmod(_KEY_PATH, 0o600)
    except OSError:
        # Best-effort on Windows where POSIX modes do not fully apply.
        logger.debug("Could not chmod install key; continuing")
    logger.info("Generated new install key at %s", _KEY_PATH)
    return key


def _get_fernet() -> Fernet:
    global _fernet
    with _lock:
        if _fernet is None:
            _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt_str(plaintext: str) -> str:
    """Encrypt a short string and return a URL-safe base64 token."""
    if not plaintext:
        return ""
    token = _get_fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_str(token: str) -> str | None:
    """
    Decrypt a token produced by :func:`encrypt_str`.

    Returns ``None`` if the token is empty, malformed, or was encrypted with a
    different install key (e.g. after the key file was rotated or deleted).
    """
    if not token:
        return None
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("Stored secret could not be decrypted with the current install key")
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Unexpected error decrypting stored secret: %s", exc)
        return None

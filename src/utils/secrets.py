"""
Per-install symmetric encryption for secrets stored at rest (e.g. BYOK Gemini key).

The Fernet master key is stored in the user's OS config directory (rather than
next to the encrypted data) so a single filesystem-read bug inside the
repo/install tree does not hand the attacker both the ciphertext and the key.

On Windows the key lives under ``%LOCALAPPDATA%\\Aegir``; on macOS under
``~/Library/Application Support/Aegir``; on Linux under
``$XDG_CONFIG_HOME/aegir`` (falling back to ``~/.config``). The directory is
overrideable via ``NETSEC_INSTALL_KEY_DIR`` for tests. Pre-rename installs
that created keys at the legacy ``NetSecAIScanner`` paths are migrated
automatically on first launch.

The encryption is intentionally transparent to the application: all callers
see plaintext strings. It is **not** a substitute for a proper secrets manager
— anyone with read access to the user's config directory can recover the
secret. The goal is defence-in-depth against casual filesystem exposure
(backups, log scrapers, accidental repo commits), not against a privileged
local attacker. In the Electron shell we plan to migrate to OS keystore
(DPAPI / Keychain / libsecret via keytar) once the native bridge ships.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from threading import Lock

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _user_config_dir() -> Path:
    """Return the per-user config directory for the install key."""
    override = os.getenv("NETSEC_INSTALL_KEY_DIR")
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "Aegir"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Aegir"

    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "aegir"


def _legacy_user_config_dirs() -> list[Path]:
    """Pre-rename config dirs to migrate keys from on first launch."""
    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
        return [Path(base) / "NetSecAIScanner"]
    if sys.platform == "darwin":
        return [Path.home() / "Library" / "Application Support" / "NetSecAIScanner"]
    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return [base / "netsec-ai-scanner"]


def _install_key_path() -> Path:
    return _user_config_dir() / "install.key"


_LEGACY_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_LEGACY_DATA_KEY_PATH = _LEGACY_DATA_DIR / ".install_key"

# Fernet keys are URL-safe base64 of a 32-byte secret → exactly 44 bytes on
# disk. Anything else is almost certainly a corrupt file or whitespace
# smuggled in by a previous implementation; refuse to use it rather than
# decrypt garbage.
_FERNET_KEY_LENGTH = 44

_fernet: Fernet | None = None
_lock = Lock()


def _validate_key_bytes(key: bytes) -> bytes:
    if len(key) != _FERNET_KEY_LENGTH:
        raise ValueError(
            f"install key is {len(key)} bytes, expected {_FERNET_KEY_LENGTH}; "
            "file appears corrupted"
        )
    # Constructor validates the base64 / key length; raises ValueError on bad data.
    Fernet(key)
    return key


def _migrate_legacy_key(new_path: Path) -> bytes | None:
    """Move an older install key to the user config dir if present.

    Two legacy locations are checked, in priority order:

    1. The pre-rename per-user config dir(s) (``NetSecAIScanner`` /
       ``netsec-ai-scanner``) used after PR #4 (H-8) but before the Aegir
       rename.
    2. The very-early ``<repo>/data/.install_key`` location used before H-8.

    The first one that yields a valid Fernet key wins; the others are left
    in place for forensics and a warning is emitted.
    """
    candidates: list[Path] = []
    for legacy_dir in _legacy_user_config_dirs():
        candidates.append(legacy_dir / "install.key")
    candidates.append(_LEGACY_DATA_KEY_PATH)

    for legacy_path in candidates:
        if not legacy_path.exists():
            continue
        try:
            legacy = legacy_path.read_bytes().strip()
            key = _validate_key_bytes(legacy)
        except Exception as exc:
            logger.warning(
                "Legacy install key at %s is unusable (%s); skipping",
                legacy_path,
                exc,
            )
            continue
        new_path.parent.mkdir(parents=True, exist_ok=True)
        new_path.write_bytes(key)
        try:
            os.chmod(new_path, 0o600)
        except OSError:
            logger.debug("Could not chmod migrated install key; continuing")
        try:
            legacy_path.unlink()
        except OSError as exc:
            logger.warning(
                "Migrated legacy install key but could not remove source %s: %s",
                legacy_path,
                exc,
            )
        logger.info("Migrated install key from %s to %s", legacy_path, new_path)
        return key

    return None


def _load_or_create_key() -> bytes:
    """Return the Fernet key, creating one on first use."""
    key_path = _install_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        return _validate_key_bytes(key_path.read_bytes().strip())

    migrated = _migrate_legacy_key(key_path)
    if migrated is not None:
        return migrated

    key = Fernet.generate_key()
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        # Best-effort on Windows where POSIX modes do not fully apply.
        logger.debug("Could not chmod install key; continuing")
    logger.info("Generated new install key at %s", key_path)
    return key


def _get_fernet() -> Fernet:
    global _fernet
    with _lock:
        if _fernet is None:
            _fernet = Fernet(_load_or_create_key())
    return _fernet


def _reset_for_tests() -> None:
    """Clear the cached Fernet handle so a test can point at a new key dir."""
    global _fernet
    with _lock:
        _fernet = None


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

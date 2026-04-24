from pathlib import Path


def _isolate_secrets(monkeypatch, tmp_path: Path):
    """Point the module at a fresh per-user config dir and reset its cache."""
    from src.utils import secrets as secrets_mod

    monkeypatch.setenv("NETSEC_INSTALL_KEY_DIR", str(tmp_path))
    secrets_mod._reset_for_tests()
    return secrets_mod


def test_encrypt_decrypt_roundtrip(tmp_path: Path, monkeypatch) -> None:
    secrets_mod = _isolate_secrets(monkeypatch, tmp_path)

    plaintext = "AIzaSy_test_token_12345"
    token = secrets_mod.encrypt_str(plaintext)
    assert token
    assert plaintext not in token  # encrypted, not just base64
    decrypted = secrets_mod.decrypt_str(token)
    assert decrypted == plaintext


def test_decrypt_bad_token_returns_none(tmp_path: Path, monkeypatch) -> None:
    secrets_mod = _isolate_secrets(monkeypatch, tmp_path)

    assert secrets_mod.decrypt_str("not-a-real-token") is None
    assert secrets_mod.decrypt_str("") is None


def test_install_key_lives_in_user_config_dir(tmp_path: Path, monkeypatch) -> None:
    """The key file must end up in the configured per-user directory."""
    secrets_mod = _isolate_secrets(monkeypatch, tmp_path)

    # Trigger key creation.
    secrets_mod.encrypt_str("trigger-creation")

    key_path = tmp_path / "install.key"
    assert key_path.exists(), f"install key not created at {key_path}"
    assert len(key_path.read_bytes().strip()) == 44


def test_corrupt_install_key_rejected(tmp_path: Path, monkeypatch) -> None:
    """A wrong-length key on disk must be rejected rather than silently coerced."""
    secrets_mod = _isolate_secrets(monkeypatch, tmp_path)

    key_path = tmp_path / "install.key"
    key_path.write_bytes(b"not-really-a-fernet-key")

    try:
        secrets_mod.encrypt_str("anything")
    except ValueError as exc:
        assert "corrupted" in str(exc)
    else:
        raise AssertionError("Expected ValueError on corrupt install key")

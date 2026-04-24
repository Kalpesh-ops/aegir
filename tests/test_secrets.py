from pathlib import Path


def test_encrypt_decrypt_roundtrip(tmp_path: Path, monkeypatch) -> None:
    from src.utils import secrets as secrets_mod

    monkeypatch.setattr(secrets_mod, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(secrets_mod, "_KEY_PATH", tmp_path / ".install_key")
    monkeypatch.setattr(secrets_mod, "_fernet", None)

    plaintext = "AIzaSy_test_token_12345"
    token = secrets_mod.encrypt_str(plaintext)
    assert token
    assert plaintext not in token  # encrypted, not just base64
    decrypted = secrets_mod.decrypt_str(token)
    assert decrypted == plaintext


def test_decrypt_bad_token_returns_none(tmp_path: Path, monkeypatch) -> None:
    from src.utils import secrets as secrets_mod

    monkeypatch.setattr(secrets_mod, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(secrets_mod, "_KEY_PATH", tmp_path / ".install_key")
    monkeypatch.setattr(secrets_mod, "_fernet", None)

    assert secrets_mod.decrypt_str("not-a-real-token") is None
    assert secrets_mod.decrypt_str("") is None

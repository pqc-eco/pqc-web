import base64
import os
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from app.crypto import decrypt_field, encrypt_field, hash_password, verify_password
from app.routes import EMAIL_CONTEXT

from tests.conftest import PASSWORD  # noqa: E402


def login(client, password=PASSWORD):
    return client.post("/login", json={"username": "alice", "password": password})


def test_health(client):
    assert client.get("/health").get_json() == {"status": "UP"}


def test_login_and_profile(client):
    r = login(client)
    assert r.status_code == 200
    token = r.get_json()["token"]
    p = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert p.status_code == 200
    assert p.get_json() == {"username": "alice", "email": "alice@example.com"}


def test_wrong_password_rejected(client):
    assert login(client, "wrong").status_code == 401


def test_unknown_user_rejected(client):
    r = client.post("/login", json={"username": "bob", "password": PASSWORD})
    assert r.status_code == 401


def test_missing_token_rejected(client):
    assert client.get("/profile").status_code == 401


def test_tampered_token_rejected(client):
    token = login(client).get_json()["token"]
    bad = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    assert client.get("/profile", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_expired_token_rejected(app, client):
    settings = app.config["SETTINGS"]
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = jwt.encode(
        {"sub": "alice", "iss": "pqc-web", "aud": "pqc-web-api",
         "iat": past, "exp": past + timedelta(minutes=5)},
        settings.private_key, algorithm="RS256",
    )
    assert client.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_with_wrong_audience_rejected(app, client):
    settings = app.config["SETTINGS"]
    token = jwt.encode(
        {"sub": "alice", "iss": "pqc-web", "aud": "other",
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.private_key, algorithm="RS256",
    )
    assert client.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_jwks_publishes_public_key(app, client):
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert keys[0]["kty"] == "RSA" and keys[0]["alg"] == "RS256"
    token = login(client).get_json()["token"]
    public = jwt.PyJWK(keys[0]).key
    assert jwt.decode(token, public, algorithms=["RS256"], audience="pqc-web-api", issuer="pqc-web")["sub"] == "alice"


def test_password_hash_roundtrip():
    stored = hash_password(PASSWORD)
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password(PASSWORD, stored)
    assert not verify_password("nope", stored)


def test_email_encryption_roundtrip():
    key = AESGCM.generate_key(bit_length=256)
    sealed = encrypt_field(key, "a@b.c", EMAIL_CONTEXT)
    assert decrypt_field(key, sealed, EMAIL_CONTEXT) == "a@b.c"
    with pytest.raises(Exception):
        decrypt_field(key, sealed, b"other-context")


def test_production_requires_keys(monkeypatch):
    from app.config import load_settings
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError):
        load_settings()

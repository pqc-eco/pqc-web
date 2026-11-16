import base64
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


from app.primitives import (
    ecdh_export, sha256_hex, sha512_hex, sign_audit_entry, unwrap_data_key,
    verify_audit_entry, verify_hmac_sha256, wrap_data_key,
)
from tests.test_api import PASSWORD, login  # reuses the app fixture


def bearer(client):
    return {"Authorization": "Bearer " + login(client).get_json()["token"]}


def test_digests_match_hashlib(client):
    r = client.post("/v1/digest", json={"data": "hello"}).get_json()
    assert r["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert r["sha512"] == hashlib.sha512(b"hello").hexdigest()


def test_webhook_signature_verified(app, client):
    settings = app.config["SETTINGS"]
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqc-web-webhook").derive(settings.data_key)
    body = b'{"event":"ping"}'
    good = hmac.new(key, body, hashlib.sha256).hexdigest()
    assert client.post("/v1/webhook/verify", data=body, headers={"X-Signature": good}).status_code == 200
    assert client.post("/v1/webhook/verify", data=body, headers={"X-Signature": "00" * 32}).status_code == 401


def test_service_token_es256_roundtrip(client):
    r = client.post("/v1/service-token", headers=bearer(client))
    assert r.status_code == 200 and r.get_json()["alg"] == "ES256"
    token = r.get_json()["token"]
    v = client.get("/v1/service-token/verify", headers={"Authorization": "Bearer " + token})
    assert v.status_code == 200 and v.get_json()["sub"] == "alice"


def test_service_token_requires_user(client):
    assert client.post("/v1/service-token").status_code == 401


def test_export_x25519_hkdf_aesgcm(client):
    peer_private = x25519.X25519PrivateKey.generate()
    peer_public = peer_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    r = client.post("/v1/export", headers=bearer(client),
                    json={"peer_public": base64.b64encode(peer_public).decode(), "payload": "secret"})
    assert r.status_code == 200
    body = r.get_json()
    eph = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(body["ephemeral_public"]))
    shared = peer_private.exchange(eph)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqc-web-export").derive(shared)
    plain = AESGCM(key).decrypt(base64.b64decode(body["nonce"]), base64.b64decode(body["ciphertext"]),
                                b"pqc-web-export")
    assert plain == b"secret"


def test_export_rejects_bad_key(client):
    r = client.post("/v1/export", headers=bearer(client), json={"peer_public": "AAAA", "payload": "x"})
    assert r.status_code == 400


def test_key_wrap_roundtrip(app):
    settings = app.config["SETTINGS"]
    data_key = AESGCM.generate_key(bit_length=256)
    wrapped = wrap_data_key(settings.private_key.public_key(), data_key)
    assert unwrap_data_key(settings.private_key, wrapped) == data_key


def test_key_wrap_endpoint(client):
    key = base64.b64encode(b"k" * 32).decode()
    r = client.post("/v1/keys/wrap", headers=bearer(client), json={"key": key})
    assert r.status_code == 200 and r.get_json()["alg"] == "RSA-OAEP-SHA256"


def test_audit_signature_verifies(app, client):
    entry = b"login alice"
    r = client.post("/v1/audit/sign", headers=bearer(client), data=entry)
    assert r.status_code == 200
    sig = base64.b64decode(r.get_json()["signature"])
    pub_pem = client.get("/v1/audit/public-key").data
    pub = serialization.load_pem_public_key(pub_pem)
    assert verify_audit_entry(pub, entry, sig)
    assert not verify_audit_entry(pub, b"tampered", sig)

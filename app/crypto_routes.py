import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Blueprint, current_app, jsonify, request

from .primitives import (
    ecdh_export, issue_es256_token, sha256_hex, sha512_hex, sign_audit_entry,
    verify_es256_token, verify_hmac_sha256, wrap_data_key,
)
from .crypto import verify_token

bp = Blueprint("crypto", __name__, url_prefix="/v1")


def _settings():
    return current_app.config["SETTINGS"]


def _require_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    s = _settings()
    try:
        return verify_token(s.private_key.public_key(), auth[7:], s.issuer, s.audience)
    except Exception:
        return None


def _webhook_key() -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pqc-web-webhook").derive(_settings().data_key)


@bp.post("/digest")
def digest():
    body = request.get_json(silent=True) or {}
    data = str(body.get("data", "")).encode("utf-8")
    return jsonify(sha256=sha256_hex(data), sha512=sha512_hex(data))


@bp.post("/webhook/verify")
def webhook_verify():
    signature = request.headers.get("X-Signature", "")
    valid = verify_hmac_sha256(_webhook_key(), request.get_data(), signature)
    return jsonify(valid=valid), (200 if valid else 401)


@bp.post("/service-token")
def service_token():
    claims = _require_user()
    if claims is None:
        return jsonify(error="user token required"), 401
    s = _settings()
    token = issue_es256_token(s.service_key, claims["sub"], s.token_ttl_minutes, s.issuer, s.audience)
    return jsonify(token=token, alg="ES256")


@bp.get("/service-token/verify")
def service_token_verify():
    auth = request.headers.get("Authorization", "")
    s = _settings()
    try:
        claims = verify_es256_token(s.service_key.public_key(), auth[7:], s.issuer, s.audience)
    except Exception:
        return jsonify(error="invalid service token"), 401
    return jsonify(claims)


@bp.post("/export")
def export():
    if _require_user() is None:
        return jsonify(error="user token required"), 401
    body = request.get_json(silent=True) or {}
    try:
        peer = base64.b64decode(body["peer_public"], validate=True)
        if len(peer) != 32:
            raise ValueError
    except Exception:
        return jsonify(error="peer_public must be a base64 X25519 public key"), 400
    payload = str(body.get("payload", "")).encode("utf-8")
    ephemeral, nonce, sealed = ecdh_export(peer, payload)
    return jsonify(
        ephemeral_public=base64.b64encode(ephemeral).decode(),
        nonce=base64.b64encode(nonce).decode(),
        ciphertext=base64.b64encode(sealed).decode(),
    )


@bp.post("/keys/wrap")
def wrap_key():
    if _require_user() is None:
        return jsonify(error="user token required"), 401
    body = request.get_json(silent=True) or {}
    try:
        data_key = base64.b64decode(body["key"], validate=True)
        if len(data_key) != 32:
            raise ValueError
    except Exception:
        return jsonify(error="key must be a base64 32-byte value"), 400
    wrapped = wrap_data_key(_settings().private_key.public_key(), data_key)
    return jsonify(wrapped=base64.b64encode(wrapped).decode(), alg="RSA-OAEP-SHA256")


@bp.post("/audit/sign")
def audit_sign():
    if _require_user() is None:
        return jsonify(error="user token required"), 401
    entry = request.get_data()
    signature = sign_audit_entry(_settings().audit_key, entry)
    return jsonify(signature=base64.b64encode(signature).decode(), alg="Ed25519")


@bp.get("/audit/public-key")
def audit_public_key():
    pem = _settings().audit_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, 200, {"Content-Type": "application/x-pem-file"}

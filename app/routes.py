import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, current_app, jsonify, request

from .crypto import decrypt_field, issue_token, verify_password, verify_token
from .models import User

bp = Blueprint("api", __name__)
EMAIL_CONTEXT = b"user-email"


def _public_key():
    return current_app.config["SETTINGS"].private_key.public_key()


@bp.get("/health")
def health():
    return jsonify(status="UP")


@bp.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    user = User.query.filter_by(username=username).first()
    if user is None or not verify_password(password, user.password_hash):
        return jsonify(error="invalid credentials"), 401
    settings = current_app.config["SETTINGS"]
    token = issue_token(settings.private_key, user.username, settings.token_ttl_minutes,
                        settings.issuer, settings.audience)
    return jsonify(token=token, token_type="Bearer", expires_in=settings.token_ttl_minutes * 60)


@bp.get("/profile")
def profile():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing token"), 401
    settings = current_app.config["SETTINGS"]
    try:
        claims = verify_token(_public_key(), auth[7:], settings.issuer, settings.audience)
    except Exception:
        return jsonify(error="invalid token"), 401
    user = User.query.filter_by(username=claims["sub"]).first()
    if user is None:
        return jsonify(error="unknown user"), 401
    email = decrypt_field(settings.data_key, user.email_encrypted, EMAIL_CONTEXT)
    return jsonify(username=user.username, email=email)


@bp.get("/.well-known/jwks.json")
def jwks():
    numbers = _public_key().public_numbers()

    def b64url(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return jsonify(keys=[{
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "pqc-web-1",
        "n": b64url(numbers.n), "e": b64url(numbers.e),
    }])

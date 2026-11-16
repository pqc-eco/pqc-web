import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        base64.b64decode(salt_b64),
        int(iterations),
    )
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


def encrypt_field(key: bytes, plaintext: str, context: bytes) -> str:
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), context)
    return base64.b64encode(nonce + sealed).decode()


def decrypt_field(key: bytes, token: str, context: bytes) -> str:
    raw = base64.b64decode(token)
    return AESGCM(key).decrypt(raw[:12], raw[12:], context).decode("utf-8")


def issue_token(private_key, subject: str, ttl_minutes: int, issuer: str, audience: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "pqc-web-1"})


def verify_token(public_key, token: str, issuer: str, audience: str) -> dict:
    return jwt.decode(token, public_key, algorithms=["RS256"], issuer=issuer, audience=audience)

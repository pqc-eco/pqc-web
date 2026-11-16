import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OAEP_SHA256 = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac_sha256(key: bytes, data: bytes, signature_hex: str) -> bool:
    return hmac.compare_digest(hmac_sha256_hex(key, data), signature_hex)


def issue_es256_token(key: ec.EllipticCurvePrivateKey, subject: str, ttl_minutes: int,
                      issuer: str, audience: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": subject, "iss": issuer, "aud": audience,
              "iat": now, "exp": now + timedelta(minutes=ttl_minutes)}
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": "pqc-web-svc-1"})


def verify_es256_token(public_key, token: str, issuer: str, audience: str) -> dict:
    return jwt.decode(token, public_key, algorithms=["ES256"], issuer=issuer, audience=audience)


def sign_audit_entry(key: ed25519.Ed25519PrivateKey, entry: bytes) -> bytes:
    return key.sign(entry)


def verify_audit_entry(public_key: ed25519.Ed25519PublicKey, entry: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, entry)
        return True
    except InvalidSignature:
        return False


def wrap_data_key(public_key, data_key: bytes) -> bytes:
    return public_key.encrypt(data_key, OAEP_SHA256)


def unwrap_data_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, OAEP_SHA256)


def _raw_public(key) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def ecdh_export(peer_public_raw: bytes, payload: bytes, info: bytes = b"pqc-web-export"):
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_raw))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    ephemeral_public = _raw_public(ephemeral.public_key())
    nonce = hashlib.sha256(ephemeral_public + peer_public_raw).digest()[:12]
    sealed = AESGCM(key).encrypt(nonce, payload, info)
    return ephemeral_public, nonce, sealed

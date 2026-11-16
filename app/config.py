import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class Settings:
    env: str
    database_url: str
    private_key: rsa.RSAPrivateKey
    data_key: bytes
    service_key: ec.EllipticCurvePrivateKey
    audit_key: ed25519.Ed25519PrivateKey
    token_ttl_minutes: int
    issuer: str
    audience: str


def _load_or_generate(env_name, loader, generator):
    pem = os.environ.get(env_name)
    return loader(pem.encode()) if pem else generator()


def load_settings(env=None):
    env = env or os.environ.get("APP_ENV", "production")
    if env == "production" and not (os.environ.get("JWT_PRIVATE_KEY_PEM") and os.environ.get("DATA_ENCRYPTION_KEY")):
        raise RuntimeError("JWT_PRIVATE_KEY_PEM and DATA_ENCRYPTION_KEY must be set in production")

    private_key = _load_or_generate(
        "JWT_PRIVATE_KEY_PEM",
        lambda pem: serialization.load_pem_private_key(pem, password=None),
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    service_key = _load_or_generate(
        "SERVICE_PRIVATE_KEY_PEM",
        lambda pem: serialization.load_pem_private_key(pem, password=None),
        lambda: ec.generate_private_key(ec.SECP256R1()),
    )
    audit_key = _load_or_generate(
        "AUDIT_PRIVATE_KEY_PEM",
        lambda pem: serialization.load_pem_private_key(pem, password=None),
        ed25519.Ed25519PrivateKey.generate,
    )

    data_key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")
    data_key = base64.b64decode(data_key_b64) if data_key_b64 else AESGCM.generate_key(bit_length=256)
    if len(data_key) != 32:
        raise RuntimeError("DATA_ENCRYPTION_KEY must decode to 32 bytes")

    return Settings(
        env=env,
        database_url=os.environ.get("DATABASE_URL", "sqlite:///app.db"),
        private_key=private_key,
        data_key=data_key,
        service_key=service_key,
        audit_key=audit_key,
        token_ttl_minutes=int(os.environ.get("TOKEN_TTL_MINUTES", "15")),
        issuer=os.environ.get("TOKEN_ISSUER", "pqc-web"),
        audience=os.environ.get("TOKEN_AUDIENCE", "pqc-web-api"),
    )

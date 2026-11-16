import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class Settings:
    env: str
    database_url: str
    private_key: rsa.RSAPrivateKey
    data_key: bytes
    token_ttl_minutes: int
    issuer: str
    audience: str


def load_settings(env=None):
    env = env or os.environ.get("APP_ENV", "production")
    pem = os.environ.get("JWT_PRIVATE_KEY_PEM")
    data_key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")
    if env == "production" and not (pem and data_key_b64):
        raise RuntimeError("JWT_PRIVATE_KEY_PEM and DATA_ENCRYPTION_KEY must be set in production")

    if pem:
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    if data_key_b64:
        data_key = base64.b64decode(data_key_b64)
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        data_key = AESGCM.generate_key(bit_length=256)
    if len(data_key) != 32:
        raise RuntimeError("DATA_ENCRYPTION_KEY must decode to 32 bytes")

    return Settings(
        env=env,
        database_url=os.environ.get("DATABASE_URL", "sqlite:///app.db"),
        private_key=private_key,
        data_key=data_key,
        token_ttl_minutes=int(os.environ.get("TOKEN_TTL_MINUTES", "15")),
        issuer=os.environ.get("TOKEN_ISSUER", "pqc-web"),
        audience=os.environ.get("TOKEN_AUDIENCE", "pqc-web-api"),
    )

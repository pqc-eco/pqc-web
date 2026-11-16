import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import create_app
from app.cli import register
from app.config import Settings
from app.crypto import encrypt_field, hash_password
from app.models import User, db
from app.routes import EMAIL_CONTEXT

PASSWORD = "correct horse battery"


@pytest.fixture
def app():
    settings = Settings(
        env="test",
        database_url="sqlite:///:memory:",
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        data_key=AESGCM.generate_key(bit_length=256),
        service_key=ec.generate_private_key(ec.SECP256R1()),
        audit_key=ed25519.Ed25519PrivateKey.generate(),
        token_ttl_minutes=15,
        issuer="pqc-web",
        audience="pqc-web-api",
    )
    app = create_app(settings)
    register(app)
    with app.app_context():
        db.create_all()
        db.session.add(User(
            username="alice",
            password_hash=hash_password(PASSWORD),
            email_encrypted=encrypt_field(settings.data_key, "alice@example.com", EMAIL_CONTEXT),
        ))
        db.session.commit()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()

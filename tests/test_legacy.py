import hashlib

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.legacy import (
    ecdh_p256_shared_key, legacy_checksum_sha256, sign_document_ecdsa_p384,
    sign_legacy_rsa_sha256, verify_document_ecdsa_p384, verify_legacy_rsa_sha256,
)


def test_legacy_rsa_signature_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = sign_legacy_rsa_sha256(key, b"partner message")
    assert verify_legacy_rsa_sha256(key.public_key(), b"partner message", sig)
    assert not verify_legacy_rsa_sha256(key.public_key(), b"tampered", sig)


def test_document_ecdsa_p384_roundtrip():
    key = ec.generate_private_key(ec.SECP384R1())
    sig = sign_document_ecdsa_p384(key, b"contract v1")
    assert verify_document_ecdsa_p384(key.public_key(), b"contract v1", sig)
    assert not verify_document_ecdsa_p384(key.public_key(), b"contract v2", sig)


def test_ecdh_both_sides_derive_same_key():
    a = ec.generate_private_key(ec.SECP256R1())
    b = ec.generate_private_key(ec.SECP256R1())
    info = b"pqc-web-partner"
    assert ecdh_p256_shared_key(a, b.public_key(), info) == ecdh_p256_shared_key(b, a.public_key(), info)


def test_legacy_sha256_checksum_matches_hashlib():
    assert legacy_checksum_sha256(b"file bytes") == hashlib.sha256(b"file bytes").hexdigest()

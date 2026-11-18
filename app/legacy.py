"""Compatibility helpers kept for partner systems that still use older algorithms."""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sign_legacy_rsa_sha256(private_key, message: bytes) -> bytes:
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def verify_legacy_rsa_sha256(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def sign_document_ecdsa_p384(private_key, document: bytes) -> bytes:
    return private_key.sign(document, ec.ECDSA(hashes.SHA384()))


def verify_document_ecdsa_p384(public_key, document: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, document, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False


def ecdh_p256_shared_key(private_key, peer_public_key, info: bytes) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def legacy_checksum_sha256(data: bytes) -> str:
    """SHA-256 checksum for partner file verification. SHA-1 was removed:
    it is broken for collision resistance and must not be used for new verifications."""
    return hashlib.sha256(data).hexdigest()

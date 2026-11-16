"""Cryptographic operations for the web app's partner exchange and storage features."""
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, ed448, x448
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def aes256_cbc_encrypt(key: bytes, plain: bytes):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, encryptor.update(data) + encryptor.finalize()


def aes256_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes128_gcm_encrypt(key: bytes, plain: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plain, aad)


def aes128_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def chacha20_poly1305_encrypt(key: bytes, plain: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plain, aad)


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def hmac_sha384(key: bytes, data: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA384())
    h.update(data)
    return h.finalize()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA512())
    h.update(data)
    return h.finalize()


def sha3_256_digest(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def sha3_512_digest(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_512())
    h.update(data)
    return h.finalize()


def blake2b_digest(data: bytes) -> bytes:
    h = hashes.Hash(hashes.BLAKE2b(64))
    h.update(data)
    return h.finalize()


def rsa_pss_sign(private_key, message: bytes) -> bytes:
    pss = asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH)
    return private_key.sign(message, pss, hashes.SHA256())


def rsa_pss_verify(public_key, message: bytes, signature: bytes) -> bool:
    pss = asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH)
    try:
        public_key.verify(signature, message, pss, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def rsa_oaep_sha1_wrap(public_key, data_key: bytes) -> bytes:
    oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    return public_key.encrypt(data_key, oaep)


def rsa_oaep_sha1_unwrap(private_key, wrapped: bytes) -> bytes:
    oaep = asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    return private_key.decrypt(wrapped, oaep)


def ecdsa_p256_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_p256_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def ed448_sign(private_key: ed448.Ed448PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed448_verify(public_key: ed448.Ed448PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def x448_shared_key(private_key: x448.X448PrivateKey, peer_public: x448.X448PublicKey, info: bytes) -> bytes:
    shared = private_key.exchange(peer_public)
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=info).derive(shared)


def hkdf_sha384_derive(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=info).derive(secret)


def scrypt_derive(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password)


def pbkdf2_sha512_derive(password: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=200_000).derive(password)

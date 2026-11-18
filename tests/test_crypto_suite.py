import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, rsa, x448

from app.crypto_suite import (
    aes128_gcm_decrypt, aes128_gcm_encrypt, aes256_cbc_decrypt, aes256_cbc_encrypt,
    blake2b_digest, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, ecdsa_p256_sign,
    ecdsa_p256_verify, ed448_sign, ed448_verify, hkdf_sha384_derive, hmac_sha384, hmac_sha512,
    pbkdf2_sha512_derive, rsa_oaep_sha256_unwrap, rsa_oaep_sha256_wrap, rsa_pss_sign, rsa_pss_verify,
    scrypt_derive, sha3_256_digest, sha3_512_digest, x448_shared_key,
)


def test_aes256_cbc_roundtrip():
    key = os.urandom(32)
    iv, ct = aes256_cbc_encrypt(key, b"partner record")
    assert aes256_cbc_decrypt(key, iv, ct) == b"partner record"


def test_aes128_gcm_roundtrip_with_aad():
    key = os.urandom(16)
    nonce, ct = aes128_gcm_encrypt(key, b"token", b"ctx")
    assert aes128_gcm_decrypt(key, nonce, ct, b"ctx") == b"token"


def test_chacha20_poly1305_roundtrip():
    key = os.urandom(32)
    nonce, ct = chacha20_poly1305_encrypt(key, b"backup")
    assert chacha20_poly1305_decrypt(key, nonce, ct) == b"backup"


def test_hmac_and_digests_have_expected_sizes():
    assert len(hmac_sha384(b"k", b"m")) == 48
    assert len(hmac_sha512(b"k", b"m")) == 64
    assert len(sha3_256_digest(b"m")) == 32
    assert len(sha3_512_digest(b"m")) == 64
    assert len(blake2b_digest(b"m")) == 64


def test_rsa_pss_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = rsa_pss_sign(key, b"contract")
    assert rsa_pss_verify(key.public_key(), b"contract", sig)
    assert not rsa_pss_verify(key.public_key(), b"other", sig)


def test_rsa_oaep_sha256_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data_key = os.urandom(32)
    wrapped = rsa_oaep_sha256_wrap(key.public_key(), data_key)
    assert rsa_oaep_sha256_unwrap(key, wrapped) == data_key


def test_ecdsa_p256_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    sig = ecdsa_p256_sign(key, b"doc")
    assert ecdsa_p256_verify(key.public_key(), b"doc", sig)


def test_ed448_roundtrip():
    key = ed448.Ed448PrivateKey.generate()
    sig = ed448_sign(key, b"log entry")
    assert ed448_verify(key.public_key(), b"log entry", sig)


def test_x448_both_sides_match():
    a = x448.X448PrivateKey.generate()
    b = x448.X448PrivateKey.generate()
    assert x448_shared_key(a, b.public_key(), b"s") == x448_shared_key(b, a.public_key(), b"s")


def test_kdfs_are_deterministic_and_sized():
    salt = b"s" * 16
    assert len(hkdf_sha384_derive(b"secret", b"info")) == 32
    assert scrypt_derive(b"pw", salt) == scrypt_derive(b"pw", salt)
    assert len(pbkdf2_sha512_derive(b"pw", salt)) == 32

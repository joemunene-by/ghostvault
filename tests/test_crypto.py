"""Tests for the low-level crypto primitives."""

from __future__ import annotations

import pytest

from ghostvault import crypto
from ghostvault.crypto import CryptoError, KDFParams


def test_kdf_deterministic_given_salt():
    salt = crypto.generate_salt()
    params = KDFParams(n=2**8, r=8, p=1)
    k1 = crypto.derive_root_key("hunter2", salt, params)
    k2 = crypto.derive_root_key("hunter2", salt, params)
    assert k1 == k2
    assert len(k1) == crypto.KEY_SIZE


def test_kdf_different_salt_different_key():
    params = KDFParams(n=2**8, r=8, p=1)
    k1 = crypto.derive_root_key("hunter2", crypto.generate_salt(), params)
    k2 = crypto.derive_root_key("hunter2", crypto.generate_salt(), params)
    assert k1 != k2


def test_aes_gcm_round_trip():
    key = crypto.generate_key()
    ct = crypto.aes_gcm_encrypt(key, b"hello world")
    assert crypto.aes_gcm_decrypt(key, ct) == b"hello world"


def test_aes_gcm_aad_round_trip():
    key = crypto.generate_key()
    ct = crypto.aes_gcm_encrypt(key, b"payload", aad=b"context")
    assert crypto.aes_gcm_decrypt(key, ct, aad=b"context") == b"payload"


def test_aes_gcm_wrong_aad_fails():
    key = crypto.generate_key()
    ct = crypto.aes_gcm_encrypt(key, b"payload", aad=b"context")
    with pytest.raises(CryptoError):
        crypto.aes_gcm_decrypt(key, ct, aad=b"other")


def test_aes_gcm_wrong_key_fails():
    ct = crypto.aes_gcm_encrypt(crypto.generate_key(), b"payload")
    with pytest.raises(CryptoError):
        crypto.aes_gcm_decrypt(crypto.generate_key(), ct)


def test_aes_gcm_tamper_fails():
    key = crypto.generate_key()
    ct = bytearray(crypto.aes_gcm_encrypt(key, b"payload"))
    ct[-1] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.aes_gcm_decrypt(key, bytes(ct))


def test_aes_gcm_short_blob_fails():
    with pytest.raises(CryptoError):
        crypto.aes_gcm_decrypt(crypto.generate_key(), b"abc")

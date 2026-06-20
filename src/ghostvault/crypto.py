"""Cryptographic primitives for ghostvault.

This module wraps vetted primitives from the `cryptography` library. It does not
invent any cryptography. The building blocks are:

- Key derivation (KDF): scrypt, deriving a 32-byte root key-encryption-key (KEK)
  from a passphrase plus a per-vault random salt.
- Authenticated encryption: AES-256-GCM for wrapping key material, for envelope
  encryption of data, and for the secret store. GCM provides confidentiality and
  integrity (authentication tag), and supports associated data (AAD) so that a
  ciphertext can be bound to a context string.

All ciphertext produced here is authenticated. Any tampering, a wrong key, or a
wrong AAD/context causes decryption to raise, never to return partial or garbage
plaintext (fail closed).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Sizes in bytes.
KEY_SIZE = 32  # AES-256
SALT_SIZE = 16
NONCE_SIZE = 12  # AES-GCM standard nonce size

# Secure scrypt defaults for interactive use. These are tunable so that the test
# suite can run with cheaper parameters while normal use keeps strong defaults.
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


class CryptoError(Exception):
    """Raised when an authenticated decryption fails (wrong key, tamper, AAD)."""


@dataclass(frozen=True)
class KDFParams:
    """Parameters for the scrypt KDF. Stored in vault metadata (not secret)."""

    n: int = DEFAULT_SCRYPT_N
    r: int = DEFAULT_SCRYPT_R
    p: int = DEFAULT_SCRYPT_P

    def to_dict(self) -> dict[str, int]:
        return {"n": self.n, "r": self.r, "p": self.p}

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> KDFParams:
        return cls(n=int(data["n"]), r=int(data["r"]), p=int(data["p"]))


def generate_salt() -> bytes:
    """Return a fresh random salt for KDF use."""
    return os.urandom(SALT_SIZE)


def generate_key() -> bytes:
    """Return a fresh random 32-byte (AES-256) symmetric key."""
    return os.urandom(KEY_SIZE)


def derive_root_key(passphrase: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive the 32-byte root KEK from a passphrase and salt using scrypt.

    Deterministic for a fixed (passphrase, salt, params) triple. The passphrase
    is never stored anywhere; only the salt and params are persisted.
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string")
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=params.n,
        r=params.r,
        p=params.p,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext-with-tag.

    The 12-byte random nonce is prepended to the output. AAD, if provided, is
    authenticated but not encrypted; the same AAD must be supplied on decrypt.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes for AES-256-GCM")
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt a nonce || ciphertext-with-tag blob produced by aes_gcm_encrypt.

    Raises CryptoError on any authentication failure (wrong key, tampered data,
    or mismatched AAD). Never returns partial or unauthenticated plaintext.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes for AES-256-GCM")
    if len(blob) < NONCE_SIZE:
        raise CryptoError("ciphertext too short to contain a nonce")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise CryptoError(
            "authentication failed: wrong key, wrong context, or tampered data"
        ) from exc

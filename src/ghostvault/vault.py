"""Vault: the key management core for ghostvault.

A vault is a directory (default ./.ghostvault) holding:

- metadata.json: vault format version, KDF salt and params, a verifier blob (to
  detect a wrong passphrase), key descriptors (id, versions, state, timestamps,
  algorithm), and per-version wrapped key material. No plaintext key bytes are
  ever stored.
- secrets.json: the secret store, each entry an envelope-encrypted blob.
- audit.log: append-only JSONL of operations.

Cryptographic design
--------------------
The root KEK is derived from a passphrase via scrypt (see crypto.py). Each named
key (a KEK) is a set of versions; each version is a random AES-256 key wrapped
(AES-GCM encrypted) under the root key at rest.

Envelope encryption: encrypt() generates a random data-encryption-key (DEK),
encrypts the plaintext with the DEK under AES-256-GCM (binding the caller's AAD
context), then wraps the DEK under the named KEK version. The output is a
self-describing, versioned blob carrying the key id, key version, wrapped DEK,
and the DEK-encrypted payload. decrypt() reverses this and verifies all tags.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import crypto
from .crypto import CryptoError, KDFParams

VAULT_FORMAT_VERSION = 1
BLOB_FORMAT_VERSION = 1
BLOB_MAGIC = "GVENV1"  # ghostvault envelope, format 1

METADATA_FILENAME = "metadata.json"
SECRETS_FILENAME = "secrets.json"
AUDIT_FILENAME = "audit.log"

DEFAULT_VAULT_DIR = ".ghostvault"

# A fixed plaintext encrypted under the root key at init. Decrypting it on open
# proves the passphrase is correct without storing the passphrase or key.
VERIFIER_PLAINTEXT = b"ghostvault-verifier-v1"
VERIFIER_AAD = b"ghostvault:verifier"


class VaultError(Exception):
    """General vault error (missing vault, unknown key, bad state)."""


class WrongPassphraseError(VaultError):
    """Raised when the supplied passphrase fails to open the vault."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass
class KeyVersion:
    """One version of a KEK: a random AES-256 key wrapped under the root key."""

    version: int
    wrapped_key: bytes  # AES-GCM blob (nonce||ct||tag) of the KEK under root key
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "wrapped_key": _b64e(self.wrapped_key),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyVersion:
        return cls(
            version=int(data["version"]),
            wrapped_key=_b64d(data["wrapped_key"]),
            created_at=data["created_at"],
        )


@dataclass
class KeyDescriptor:
    """A named KEK with one or more versions and a lifecycle state."""

    key_id: str
    algorithm: str
    state: str  # "enabled" or "disabled"
    created_at: str
    rotated_at: str
    versions: list[KeyVersion] = field(default_factory=list)

    @property
    def latest_version(self) -> int:
        return max(v.version for v in self.versions)

    def get_version(self, version: int) -> KeyVersion:
        for v in self.versions:
            if v.version == version:
                return v
        raise VaultError(f"key '{self.key_id}' has no version {version}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "state": self.state,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "versions": [v.to_dict() for v in self.versions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyDescriptor:
        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            state=data["state"],
            created_at=data["created_at"],
            rotated_at=data["rotated_at"],
            versions=[KeyVersion.from_dict(v) for v in data["versions"]],
        )


class Vault:
    """An opened vault. Holds the derived root key in memory for the session."""

    def __init__(self, path: Path, metadata: dict[str, Any], root_key: bytes):
        self.path = path
        self._metadata = metadata
        self._root_key = root_key
        self._keys: dict[str, KeyDescriptor] = {
            k["key_id"]: KeyDescriptor.from_dict(k)
            for k in metadata.get("keys", [])
        }

    # -- paths ---------------------------------------------------------------

    @property
    def metadata_path(self) -> Path:
        return self.path / METADATA_FILENAME

    @property
    def secrets_path(self) -> Path:
        return self.path / SECRETS_FILENAME

    @property
    def audit_path(self) -> Path:
        return self.path / AUDIT_FILENAME

    # -- lifecycle: init / open ---------------------------------------------

    @classmethod
    def init(
        cls,
        path: Path,
        passphrase: str,
        kdf_params: KDFParams | None = None,
    ) -> Vault:
        """Create a brand new vault at `path`. Fails if one already exists."""
        path = Path(path)
        meta_path = path / METADATA_FILENAME
        if meta_path.exists():
            raise VaultError(f"a vault already exists at {path}")
        params = kdf_params or KDFParams()
        salt = crypto.generate_salt()
        root_key = crypto.derive_root_key(passphrase, salt, params)
        verifier = crypto.aes_gcm_encrypt(root_key, VERIFIER_PLAINTEXT, VERIFIER_AAD)

        metadata: dict[str, Any] = {
            "format_version": VAULT_FORMAT_VERSION,
            "created_at": _now(),
            "kdf": "scrypt",
            "kdf_salt": _b64e(salt),
            "kdf_params": params.to_dict(),
            "verifier": _b64e(verifier),
            "keys": [],
        }
        path.mkdir(parents=True, exist_ok=True)
        vault = cls(path, metadata, root_key)
        vault._save_metadata()
        if not vault.secrets_path.exists():
            vault._write_secrets({})
        vault.audit("init", key_id=None, success=True)
        return vault

    @classmethod
    def open(cls, path: Path, passphrase: str) -> Vault:
        """Open an existing vault, verifying the passphrase."""
        path = Path(path)
        meta_path = path / METADATA_FILENAME
        if not meta_path.exists():
            raise VaultError(f"no vault found at {path}")
        metadata = json.loads(meta_path.read_text())
        salt = _b64d(metadata["kdf_salt"])
        params = KDFParams.from_dict(metadata["kdf_params"])
        root_key = crypto.derive_root_key(passphrase, salt, params)
        verifier = _b64d(metadata["verifier"])
        try:
            pt = crypto.aes_gcm_decrypt(root_key, verifier, VERIFIER_AAD)
        except CryptoError as exc:
            raise WrongPassphraseError("incorrect passphrase for vault") from exc
        if pt != VERIFIER_PLAINTEXT:
            raise WrongPassphraseError("incorrect passphrase for vault")
        return cls(path, metadata, root_key)

    # -- metadata persistence ------------------------------------------------

    def _save_metadata(self) -> None:
        self._metadata["keys"] = [k.to_dict() for k in self._keys.values()]
        tmp = self.metadata_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._metadata, indent=2, sort_keys=True))
        os.replace(tmp, self.metadata_path)

    def _read_secrets(self) -> dict[str, Any]:
        if not self.secrets_path.exists():
            return {}
        return json.loads(self.secrets_path.read_text())

    def _write_secrets(self, secrets: dict[str, Any]) -> None:
        tmp = self.secrets_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(secrets, indent=2, sort_keys=True))
        os.replace(tmp, self.secrets_path)

    # -- audit ---------------------------------------------------------------

    def audit(self, op: str, key_id: str | None, success: bool, detail: str = "") -> None:
        entry = {
            "ts": _now(),
            "op": op,
            "key_id": key_id,
            "success": success,
        }
        if detail:
            entry["detail"] = detail
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")

    def read_audit(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in self.audit_path.read_text().splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    # -- key management ------------------------------------------------------

    def _unwrap_key(self, kv: KeyVersion) -> bytes:
        return crypto.aes_gcm_decrypt(self._root_key, kv.wrapped_key)

    def _wrap_key(self, raw_key: bytes) -> bytes:
        return crypto.aes_gcm_encrypt(self._root_key, raw_key)

    def list_keys(self) -> list[KeyDescriptor]:
        return list(self._keys.values())

    def get_key(self, key_id: str) -> KeyDescriptor:
        if key_id not in self._keys:
            raise VaultError(f"unknown key id: {key_id}")
        return self._keys[key_id]

    def create_key(self, key_id: str) -> KeyDescriptor:
        if key_id in self._keys:
            raise VaultError(f"key id already exists: {key_id}")
        raw = crypto.generate_key()
        now = _now()
        kv = KeyVersion(version=1, wrapped_key=self._wrap_key(raw), created_at=now)
        desc = KeyDescriptor(
            key_id=key_id,
            algorithm="AES-256-GCM",
            state="enabled",
            created_at=now,
            rotated_at=now,
            versions=[kv],
        )
        self._keys[key_id] = desc
        self._save_metadata()
        self.audit("key.create", key_id=key_id, success=True)
        return desc

    def rotate_key(self, key_id: str) -> KeyDescriptor:
        desc = self.get_key(key_id)
        raw = crypto.generate_key()
        now = _now()
        new_version = desc.latest_version + 1
        desc.versions.append(
            KeyVersion(
                version=new_version,
                wrapped_key=self._wrap_key(raw),
                created_at=now,
            )
        )
        desc.rotated_at = now
        self._save_metadata()
        self.audit("key.rotate", key_id=key_id, success=True, detail=f"v{new_version}")
        return desc

    def disable_key(self, key_id: str) -> KeyDescriptor:
        desc = self.get_key(key_id)
        desc.state = "disabled"
        self._save_metadata()
        self.audit("key.disable", key_id=key_id, success=True)
        return desc

    def enable_key(self, key_id: str) -> KeyDescriptor:
        desc = self.get_key(key_id)
        desc.state = "enabled"
        self._save_metadata()
        self.audit("key.enable", key_id=key_id, success=True)
        return desc

    # -- envelope encryption -------------------------------------------------

    def encrypt(self, key_id: str, plaintext: bytes, context: str = "") -> dict[str, Any]:
        """Envelope-encrypt plaintext under the latest version of key_id.

        Returns a self-describing dict (the ciphertext blob). The context string,
        if any, is bound as AAD to the data layer so decryption must supply the
        same context.
        """
        desc = self.get_key(key_id)
        if desc.state != "enabled":
            self.audit("encrypt", key_id=key_id, success=False, detail="key disabled")
            raise VaultError(f"key '{key_id}' is disabled and cannot encrypt")
        version = desc.latest_version
        kek = self._unwrap_key(desc.get_version(version))

        dek = crypto.generate_key()
        aad = context.encode("utf-8") if context else None
        data_ct = crypto.aes_gcm_encrypt(dek, plaintext, aad)
        wrapped_dek = crypto.aes_gcm_encrypt(kek, dek)

        blob = {
            "magic": BLOB_MAGIC,
            "format_version": BLOB_FORMAT_VERSION,
            "key_id": key_id,
            "key_version": version,
            "algorithm": "AES-256-GCM",
            "context": context,
            "wrapped_dek": _b64e(wrapped_dek),
            "ciphertext": _b64e(data_ct),
        }
        self.audit("encrypt", key_id=key_id, success=True, detail=f"v{version}")
        return blob

    def decrypt(self, blob: dict[str, Any], context: str | None = None) -> bytes:
        """Reverse envelope encryption. Verifies all authentication tags.

        If `context` is provided it must match what was used at encryption time;
        otherwise the context recorded in the blob is used. Any mismatch causes a
        CryptoError (fail closed).
        """
        if blob.get("magic") != BLOB_MAGIC:
            raise VaultError("not a ghostvault envelope blob")
        key_id = blob["key_id"]
        version = int(blob["key_version"])
        desc = self.get_key(key_id)
        kv = desc.get_version(version)
        kek = self._unwrap_key(kv)

        wrapped_dek = _b64d(blob["wrapped_dek"])
        data_ct = _b64d(blob["ciphertext"])
        use_context = blob.get("context", "") if context is None else context
        aad = use_context.encode("utf-8") if use_context else None

        try:
            dek = crypto.aes_gcm_decrypt(kek, wrapped_dek)
            plaintext = crypto.aes_gcm_decrypt(dek, data_ct, aad)
        except CryptoError:
            self.audit("decrypt", key_id=key_id, success=False)
            raise
        self.audit("decrypt", key_id=key_id, success=True, detail=f"v{version}")
        return plaintext

    # -- secret store (seal / unseal) ---------------------------------------

    def seal(self, name: str, secret: bytes, key_id: str, context: str = "") -> None:
        """Encrypt and store a named secret under the envelope scheme."""
        blob = self.encrypt(key_id, secret, context=context)
        secrets = self._read_secrets()
        secrets[name] = {"created_at": _now(), "blob": blob}
        self._write_secrets(secrets)
        self.audit("seal", key_id=key_id, success=True, detail=name)

    def unseal(self, name: str, context: str | None = None) -> bytes:
        """Retrieve and decrypt a named secret from the store."""
        secrets = self._read_secrets()
        if name not in secrets:
            raise VaultError(f"no sealed secret named: {name}")
        blob = secrets[name]["blob"]
        plaintext = self.decrypt(blob, context=context)
        self.audit("unseal", key_id=blob.get("key_id"), success=True, detail=name)
        return plaintext

    def list_secrets(self) -> list[str]:
        return sorted(self._read_secrets().keys())

"""Tests for the vault key management core."""

from __future__ import annotations

import json

import pytest

from ghostvault.crypto import CryptoError
from ghostvault.vault import Vault, VaultError, WrongPassphraseError

from .conftest import TEST_KDF_PARAMS, TEST_PASSPHRASE

# -- open / passphrase -------------------------------------------------------


def test_open_wrong_passphrase_fails(vault_path):
    Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)
    with pytest.raises(WrongPassphraseError):
        Vault.open(vault_path, "not-the-passphrase")


def test_open_correct_passphrase_succeeds(vault_path):
    Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)
    v = Vault.open(vault_path, TEST_PASSPHRASE)
    assert v is not None


def test_open_missing_vault_fails(tmp_path):
    with pytest.raises(VaultError):
        Vault.open(tmp_path / "nope", TEST_PASSPHRASE)


def test_init_twice_fails(vault_path):
    Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)
    with pytest.raises(VaultError):
        Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)


# -- key lifecycle -----------------------------------------------------------


def test_key_create_list(vault):
    vault.create_key("app")
    keys = vault.list_keys()
    assert [k.key_id for k in keys] == ["app"]
    assert keys[0].state == "enabled"
    assert keys[0].latest_version == 1


def test_key_create_duplicate_fails(vault):
    vault.create_key("app")
    with pytest.raises(VaultError):
        vault.create_key("app")


def test_unknown_key_fails(vault):
    with pytest.raises(VaultError):
        vault.encrypt("ghost", b"data")


def test_disable_blocks_new_encryption(vault):
    vault.create_key("app")
    vault.disable_key("app")
    with pytest.raises(VaultError):
        vault.encrypt("app", b"data")


def test_disabled_key_still_decrypts(vault):
    vault.create_key("app")
    blob = vault.encrypt("app", b"secret data")
    vault.disable_key("app")
    # Disabling blocks new encryption but existing ciphertext still decrypts.
    assert vault.decrypt(blob) == b"secret data"


# -- envelope round trip -----------------------------------------------------


@pytest.mark.parametrize(
    "plaintext",
    [b"", b"a", b"hello world", b"\x00\x01\x02\xff" * 100, bytes(range(256)) * 50],
)
def test_encrypt_decrypt_round_trip(vault, plaintext):
    vault.create_key("app")
    blob = vault.encrypt("app", plaintext)
    assert vault.decrypt(blob) == plaintext


def test_metadata_has_no_plaintext_key(vault):
    vault.create_key("app")
    raw = vault.encrypt("app", b"super secret plaintext value here")
    # The data layer key (DEK) and KEK never appear in plaintext anywhere.
    meta_text = vault.metadata_path.read_text()
    assert "super secret plaintext" not in meta_text
    # The blob carries only wrapped material, not raw keys.
    assert set(raw.keys()) >= {"wrapped_dek", "ciphertext", "key_id", "key_version"}


def test_blob_is_self_describing(vault):
    vault.create_key("app")
    blob = vault.encrypt("app", b"data", context="ctx")
    assert blob["key_id"] == "app"
    assert blob["key_version"] == 1
    assert blob["context"] == "ctx"
    assert blob["algorithm"] == "AES-256-GCM"


# -- AAD / context -----------------------------------------------------------


def test_context_right_succeeds(vault):
    vault.create_key("app")
    blob = vault.encrypt("app", b"data", context="tenant-a")
    assert vault.decrypt(blob, context="tenant-a") == b"data"


def test_context_wrong_fails(vault):
    vault.create_key("app")
    blob = vault.encrypt("app", b"data", context="tenant-a")
    with pytest.raises(CryptoError):
        vault.decrypt(blob, context="tenant-b")


def test_context_recorded_used_by_default(vault):
    vault.create_key("app")
    blob = vault.encrypt("app", b"data", context="bound")
    # No explicit context on decrypt: the blob's recorded context is used.
    assert vault.decrypt(blob) == b"data"


# -- tampering ---------------------------------------------------------------


def test_tampered_ciphertext_fails(vault):
    import base64

    vault.create_key("app")
    blob = vault.encrypt("app", b"important")
    raw = base64.b64decode(blob["ciphertext"])
    tampered = bytearray(raw)
    tampered[-1] ^= 0x01
    blob["ciphertext"] = base64.b64encode(bytes(tampered)).decode("ascii")
    with pytest.raises(CryptoError):
        vault.decrypt(blob)


def test_tampered_wrapped_dek_fails(vault):
    import base64

    vault.create_key("app")
    blob = vault.encrypt("app", b"important")
    raw = base64.b64decode(blob["wrapped_dek"])
    tampered = bytearray(raw)
    tampered[0] ^= 0x80
    blob["wrapped_dek"] = base64.b64encode(bytes(tampered)).decode("ascii")
    with pytest.raises(CryptoError):
        vault.decrypt(blob)


# -- rotation ----------------------------------------------------------------


def test_rotation_uses_new_version(vault):
    vault.create_key("app")
    vault.rotate_key("app")
    blob = vault.encrypt("app", b"after rotation")
    assert blob["key_version"] == 2


def test_old_version_still_decrypts_after_rotation(vault):
    vault.create_key("app")
    old_blob = vault.encrypt("app", b"encrypted before rotation")
    assert old_blob["key_version"] == 1
    vault.rotate_key("app")
    new_blob = vault.encrypt("app", b"encrypted after rotation")
    assert new_blob["key_version"] == 2
    # Both decrypt correctly.
    assert vault.decrypt(old_blob) == b"encrypted before rotation"
    assert vault.decrypt(new_blob) == b"encrypted after rotation"


def test_rotation_persists(vault_path):
    v = Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)
    v.create_key("app")
    v.rotate_key("app")
    reopened = Vault.open(vault_path, TEST_PASSPHRASE)
    assert reopened.get_key("app").latest_version == 2


# -- seal / unseal -----------------------------------------------------------


def test_seal_unseal_round_trip(vault):
    vault.create_key("app")
    vault.seal("db-password", b"s3cr3t-p@ss", "app")
    assert vault.unseal("db-password") == b"s3cr3t-p@ss"


def test_unseal_missing_fails(vault):
    vault.create_key("app")
    with pytest.raises(VaultError):
        vault.unseal("does-not-exist")


def test_seal_unseal_with_context(vault):
    vault.create_key("app")
    vault.seal("token", b"abc123", "app", context="prod")
    assert vault.unseal("token", context="prod") == b"abc123"
    with pytest.raises(CryptoError):
        vault.unseal("token", context="dev")


def test_list_secrets(vault):
    vault.create_key("app")
    vault.seal("one", b"1", "app")
    vault.seal("two", b"2", "app")
    assert vault.list_secrets() == ["one", "two"]


# -- audit -------------------------------------------------------------------


def test_audit_records_operations(vault):
    vault.create_key("app")
    vault.encrypt("app", b"data")
    ops = [e["op"] for e in vault.read_audit()]
    assert "init" in ops
    assert "key.create" in ops
    assert "encrypt" in ops


def test_audit_records_success_flag(vault):
    vault.create_key("app")
    vault.disable_key("app")
    with pytest.raises(VaultError):
        vault.encrypt("app", b"data")
    failures = [e for e in vault.read_audit() if not e["success"]]
    assert any(e["op"] == "encrypt" for e in failures)


def test_audit_is_jsonl(vault):
    vault.create_key("app")
    for line in vault.audit_path.read_text().splitlines():
        json.loads(line)  # each line must parse independently

"""Shared pytest fixtures.

Uses cheap KDF parameters so the suite runs fast. Production code keeps the
secure scrypt defaults defined in ghostvault.crypto.
"""

from __future__ import annotations

import pytest

from ghostvault.crypto import KDFParams
from ghostvault.vault import Vault

# Deliberately weak scrypt params for speed in tests only.
TEST_KDF_PARAMS = KDFParams(n=2**8, r=8, p=1)
TEST_PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault"


@pytest.fixture
def vault(vault_path):
    return Vault.init(vault_path, TEST_PASSPHRASE, kdf_params=TEST_KDF_PARAMS)

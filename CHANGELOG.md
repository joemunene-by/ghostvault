# Changelog

All notable changes to this project are documented here. The format is based on
Keep a Changelog, and this project adheres to semantic versioning.

## [0.1.0] - 2026-06-21

### Added

- Initial release of ghostvault, a key management system with envelope encryption.
- Vault initialization with a scrypt-derived root key-encryption-key (KEK) and a
  passphrase verifier (no passphrase or key material stored in plaintext).
- Key management: create, list, rotate (new versions), disable, and enable.
- DEK/KEK envelope encryption and decryption with AES-256-GCM, producing a
  self-describing versioned ciphertext blob.
- Associated data (AAD) context binding for ciphertext.
- Secret store: seal and unseal named secrets via the envelope scheme.
- Append-only JSONL audit log of operations.
- Typer command line interface with rich output: init, key create/list/rotate/disable,
  encrypt, decrypt, seal, unseal, audit, version.
- Passphrase handling via the GHOSTVAULT_PASSPHRASE environment variable or prompt.
- Test suite covering round trips, AAD binding, tamper detection, wrong passphrase,
  rotation, key lifecycle, seal/unseal, KDF determinism, and the CLI flow.
- Continuous integration running ruff and pytest on Python 3.11 and 3.12.

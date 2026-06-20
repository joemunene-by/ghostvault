"""ghostvault: a key management system with envelope encryption.

ghostvault is a defensive command-line tool that generates and manages
cryptographic keys, supports key rotation, performs DEK/KEK envelope encryption
and decryption, seals and unseals secrets, and keeps an append-only audit log.
It uses vetted primitives from the `cryptography` library.
"""

from .crypto import CryptoError, KDFParams
from .vault import Vault, VaultError, WrongPassphraseError

__version__ = "0.1.0"

__all__ = [
    "Vault",
    "VaultError",
    "WrongPassphraseError",
    "CryptoError",
    "KDFParams",
    "__version__",
]

"""Packlier: encrypted NumPy arrays, without implicit decryption."""

from .updates import (
    PacklierUpdateError,
    PacklierUpdatedRestartRequired,
    import_update_guard,
)

__version__ = "0.1.1"

with import_update_guard(__version__, __file__):
    from .paillier import (
        EncryptedNumber,
        PaillierPrivateKey,
        PaillierPublicKey,
        generate_paillier_keypair,
        toEncryptedNumber,
    )

__all__ = [
    "EncryptedNumber",
    "PaillierPrivateKey",
    "PaillierPublicKey",
    "generate_paillier_keypair",
    "toEncryptedNumber",
    "PacklierUpdateError",
    "PacklierUpdatedRestartRequired",
]

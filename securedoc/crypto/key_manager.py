"""Generate RSA-3072 keys and store private keys as encrypted PKCS#8 PEM."""

import os
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securedoc.utils.exceptions import IncorrectPasswordError, KeyManagementError

RSA_KEY_SIZE = 3072
MAX_PEM_BYTES = 64 * 1024
MIN_PASSWORD_LENGTH = 12
_ENCRYPTED_PEM_HEADER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate an RSA-3072 identity key using the library's secure randomness."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Encode an RSA public key in interoperable SubjectPublicKeyInfo PEM."""
    _require_rsa_public_key(public_key)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def save_public_key(public_key: rsa.RSAPublicKey, path: Path) -> None:
    """Write a public PEM only if the destination does not already exist."""
    _write_new_file(path, serialize_public_key(public_key), mode=0o644)


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    """Read a bounded PEM file and require an RSA key of at least 3072 bits."""
    pem = _read_bounded_pem(path)
    try:
        public_key = serialization.load_pem_public_key(pem)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyManagementError("Invalid or unsupported public-key PEM.") from exc
    _require_rsa_public_key(public_key)
    return public_key


def save_private_key(private_key: rsa.RSAPrivateKey, path: Path, password: str) -> None:
    """Save an RSA key encrypted at rest; never overwrite an existing file."""
    _require_rsa_private_key(private_key)
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise KeyManagementError(
            "Use a private-key password of at least 12 characters."
        )

    # cryptography chooses and implements the password-based encryption scheme.
    try:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
    except ValueError as exc:
        raise KeyManagementError("Could not encrypt private key.") from exc
    _write_new_file(path, pem, mode=0o600)


def load_private_key(path: Path, password: str) -> rsa.RSAPrivateKey:
    """Unlock an encrypted RSA PEM; reject plaintext and non-RSA key files."""
    if not isinstance(password, str):
        raise IncorrectPasswordError("Private-key password must be text.")
    pem = _read_bounded_pem(path)
    if not pem.startswith(_ENCRYPTED_PEM_HEADER):
        raise KeyManagementError("Only encrypted PKCS#8 private-key PEM is accepted.")
    try:
        private_key = serialization.load_pem_private_key(
            pem, password=password.encode("utf-8")
        )
    except ValueError as exc:
        # cryptography reports either a wrong password or corrupted PEM here.
        raise IncorrectPasswordError(
            "Unable to unlock private key. Check the password and key file."
        ) from exc
    except (TypeError, UnsupportedAlgorithm) as exc:
        raise KeyManagementError(
            "Invalid or unsupported encrypted private key."
        ) from exc
    _require_rsa_private_key(private_key)
    return private_key


def _read_bounded_pem(path: Path) -> bytes:
    """Limit hostile or accidental oversized files before parsing them."""
    try:
        with Path(path).open("rb") as key_file:
            pem = key_file.read(MAX_PEM_BYTES + 1)
    except OSError as exc:
        raise KeyManagementError("Could not read the key file.") from exc
    if not pem or len(pem) > MAX_PEM_BYTES:
        raise KeyManagementError("Key file is empty or unreasonably large.")
    return pem


def _write_new_file(path: Path, pem: bytes, *, mode: int) -> None:
    """Create a file exclusively so a saved key cannot replace an existing one."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(Path(path), flags, mode)
    except FileExistsError as exc:
        raise KeyManagementError("Key file already exists; choose a new path.") from exc
    except OSError as exc:
        raise KeyManagementError("Could not create the key file.") from exc
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(pem)
            key_file.flush()
            os.fsync(key_file.fileno())
    except OSError as exc:
        raise KeyManagementError("Could not finish writing the key file.") from exc


def _require_rsa_public_key(public_key: object) -> None:
    if (
        not isinstance(public_key, rsa.RSAPublicKey)
        or public_key.key_size < RSA_KEY_SIZE
    ):
        raise KeyManagementError("An RSA public key of at least 3072 bits is required.")


def _require_rsa_private_key(private_key: object) -> None:
    if (
        not isinstance(private_key, rsa.RSAPrivateKey)
        or private_key.key_size < RSA_KEY_SIZE
    ):
        raise KeyManagementError(
            "An RSA private key of at least 3072 bits is required."
        )

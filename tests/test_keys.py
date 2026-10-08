"""Exercise key generation, PEM storage, and rejected key/password inputs."""

import os
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from securedoc.crypto.key_manager import (
    MAX_PEM_BYTES,
    generate_rsa_private_key,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    serialize_public_key,
)
from securedoc.utils.exceptions import IncorrectPasswordError, KeyManagementError


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """One expensive RSA generation can serve independent read-only tests."""
    return generate_rsa_private_key()


@pytest.fixture(scope="module")
def password() -> str:
    """A random test-only password; no real credential is in the source tree."""
    return secrets.token_urlsafe(32)


def test_generated_key_uses_rsa_3072(rsa_key: rsa.RSAPrivateKey) -> None:
    assert rsa_key.key_size == 3072
    assert rsa_key.public_key().public_numbers().e == 65537


def test_private_key_is_encrypted_and_loads_with_password(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey, password: str
) -> None:
    path = tmp_path / "alice.key"
    save_private_key(rsa_key, path, password)
    pem = path.read_bytes()

    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
    assert b"-----BEGIN PRIVATE KEY-----" not in pem
    assert b"-----BEGIN RSA PRIVATE KEY-----" not in pem
    assert password.encode("utf-8") not in pem
    assert (
        load_private_key(path, password).private_numbers() == rsa_key.private_numbers()
    )
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_wrong_password_is_rejected(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey, password: str
) -> None:
    path = tmp_path / "alice.key"
    save_private_key(rsa_key, path, password)
    with pytest.raises(IncorrectPasswordError, match="Unable to unlock"):
        load_private_key(path, password + "-wrong")


def test_short_password_is_rejected_without_creating_a_file(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = tmp_path / "alice.key"
    with pytest.raises(KeyManagementError, match="at least 12"):
        save_private_key(rsa_key, path, "x" * 11)
    assert not path.exists()


def test_existing_file_is_not_overwritten(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey, password: str
) -> None:
    path = tmp_path / "alice.key"
    path.write_bytes(b"original user file")
    with pytest.raises(KeyManagementError, match="already exists"):
        save_private_key(rsa_key, path, password)
    assert path.read_bytes() == b"original user file"


def test_public_key_serialization_and_load(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = tmp_path / "alice.pub"
    public_key = rsa_key.public_key()
    assert serialize_public_key(public_key).startswith(b"-----BEGIN PUBLIC KEY-----")
    save_public_key(public_key, path)
    assert path.read_bytes() == serialize_public_key(public_key)
    assert load_public_key(path).public_numbers() == public_key.public_numbers()


def test_plaintext_private_key_is_rejected(tmp_path: Path) -> None:
    # A fake PEM header is enough to test the guard; never write a real
    # unencrypted private key, including in a temporary test directory.
    path = tmp_path / "insecure.key"
    path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n")
    with pytest.raises(KeyManagementError, match="Only encrypted"):
        load_private_key(path, secrets.token_urlsafe(32))


def test_corrupted_encrypted_key_fails_safely(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey, password: str
) -> None:
    path = tmp_path / "alice.key"
    save_private_key(rsa_key, path, password)
    pem = path.read_bytes()
    path.write_bytes(pem[:50] + b"!" + pem[51:])
    with pytest.raises(IncorrectPasswordError, match="password and key file"):
        load_private_key(path, password)


def test_unicode_password_round_trip(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = tmp_path / "unicode.key"
    password = secrets.token_urlsafe(32) + "नमस्ते"
    save_private_key(rsa_key, path, password)
    assert (
        load_private_key(path, password).public_key().public_numbers()
        == rsa_key.public_key().public_numbers()
    )


def test_missing_key_file_reports_safe_error(tmp_path: Path, password: str) -> None:
    with pytest.raises(KeyManagementError, match="Could not read"):
        load_private_key(tmp_path / "missing.key", password)


def test_public_key_cannot_overwrite_existing_file(
    tmp_path: Path, rsa_key: rsa.RSAPrivateKey
) -> None:
    path = tmp_path / "existing.pub"
    path.write_bytes(b"existing data")
    with pytest.raises(KeyManagementError, match="already exists"):
        save_public_key(rsa_key.public_key(), path)
    assert path.read_bytes() == b"existing data"


def test_encrypted_non_rsa_private_key_is_rejected(
    tmp_path: Path, password: str
) -> None:
    path = tmp_path / "ec.key"
    ec_key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )
    with pytest.raises(KeyManagementError, match="RSA private key"):
        load_private_key(path, password)


def test_rsa_2048_private_key_is_rejected(tmp_path: Path, password: str) -> None:
    path = tmp_path / "weak.key"
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(KeyManagementError, match="at least 3072"):
        save_private_key(weak_key, path, password)
    assert not path.exists()


def test_malformed_or_oversized_public_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pub"
    path.write_bytes(b"not a PEM")
    with pytest.raises(KeyManagementError, match="Invalid or unsupported"):
        load_public_key(path)
    path.write_bytes(b"x" * (MAX_PEM_BYTES + 1))
    with pytest.raises(KeyManagementError, match="unreasonably large"):
        load_public_key(path)


def test_non_rsa_public_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ec.pub"
    ec_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    path.write_bytes(
        ec_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(KeyManagementError, match="RSA public key"):
        load_public_key(path)


def test_weak_rsa_public_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "weak.pub"
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        weak_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(KeyManagementError, match="at least 3072"):
        load_public_key(path)

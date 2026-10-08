"""Real X.509 issuance, parsing, and rejection of malformed CA inputs."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from securedoc.crypto.certificates import (
    MAX_CERTIFICATE_BYTES,
    certificate_fingerprint,
    create_root_ca,
    issue_user_certificate,
    load_certificate,
    serialize_certificate,
)
from securedoc.crypto.key_manager import generate_rsa_private_key
from securedoc.utils.exceptions import CertificateError


@pytest.fixture(scope="module")
def ca_key() -> rsa.RSAPrivateKey:
    return generate_rsa_private_key()


@pytest.fixture(scope="module")
def root(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    return create_root_ca(ca_key)


@pytest.fixture(scope="module")
def user_key() -> rsa.RSAPrivateKey:
    return generate_rsa_private_key()


def test_root_is_self_signed_ca_with_sha256_pss(
    root: x509.Certificate, ca_key: rsa.RSAPrivateKey
) -> None:
    assert root.subject == root.issuer
    assert root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "SecureDoc Root CA"
    )
    assert root.public_key().public_numbers() == ca_key.public_key().public_numbers()
    assert root.serial_number > 0
    assert root.signature_hash_algorithm.name == "sha256"
    assert isinstance(root.signature_algorithm_parameters, padding.PSS)
    root.verify_directly_issued_by(root)
    constraints = root.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical and constraints.value.ca
    assert constraints.value.path_length == 0
    usage = root.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.key_cert_sign


def test_user_certificate_has_correct_issuer_key_and_restricted_usage(
    root: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    user_key: rsa.RSAPrivateKey,
) -> None:
    user = issue_user_certificate(
        root,
        ca_key,
        user_key.public_key(),
        common_name="Alice",
        organization="Demo University",
    )
    user.verify_directly_issued_by(root)
    assert user.issuer == root.subject
    assert user.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Alice"
    assert user.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == (
        "Demo University"
    )
    assert user.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "NP"
    assert user.public_key().public_numbers() == user_key.public_key().public_numbers()
    assert user.serial_number != root.serial_number
    assert user.signature_hash_algorithm.name == "sha256"
    assert isinstance(user.signature_algorithm_parameters, padding.PSS)
    assert user.not_valid_after_utc <= root.not_valid_after_utc
    constraints = user.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical and not constraints.value.ca
    usage = user.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.digital_signature
    assert usage.value.key_encipherment
    assert not usage.value.key_cert_sign
    aki = user.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert aki.key_identifier == ski.digest


def test_certificate_pem_round_trip_and_fingerprint(root: x509.Certificate) -> None:
    pem = serialize_certificate(root)
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----\n")
    loaded = load_certificate(pem)
    fingerprint = certificate_fingerprint(loaded)
    assert fingerprint == root.fingerprint(hashes.SHA256()).hex().upper()
    assert len(fingerprint) == 64
    different_root = create_root_ca(generate_rsa_private_key())
    assert fingerprint != certificate_fingerprint(different_root)


@pytest.mark.parametrize(
    "bad_pem",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not a certificate", id="invalid-pem"),
        pytest.param(b"x" * (MAX_CERTIFICATE_BYTES + 1), id="oversized"),
        pytest.param("text", id="wrong-type"),
    ],
)
def test_malformed_certificate_is_rejected(bad_pem: object) -> None:
    with pytest.raises(CertificateError):
        load_certificate(bad_pem)  # type: ignore[arg-type]


def test_wrong_ca_key_cannot_issue(
    root: x509.Certificate, user_key: rsa.RSAPrivateKey
) -> None:
    with pytest.raises(CertificateError, match="identity, key, or validity"):
        issue_user_certificate(
            root,
            user_key,
            user_key.public_key(),
            common_name="Bob",
            organization="Demo University",
        )


def test_user_certificate_cannot_issue(
    root: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    user_key: rsa.RSAPrivateKey,
) -> None:
    user = issue_user_certificate(
        root,
        ca_key,
        user_key.public_key(),
        common_name="Alice",
        organization="Demo University",
    )
    with pytest.raises(CertificateError):
        issue_user_certificate(
            user,
            user_key,
            ca_key.public_key(),
            common_name="Bob",
            organization="Demo University",
        )


def test_expired_root_cannot_issue(ca_key: rsa.RSAPrivateKey) -> None:
    now = datetime.now(UTC)
    name = create_root_ca(ca_key).subject
    expired = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with pytest.raises(CertificateError, match="identity, key, or validity"):
        issue_user_certificate(
            expired,
            ca_key,
            ca_key.public_key(),
            common_name="Alice",
            organization="Demo University",
        )


def test_forged_ca_signature_cannot_issue(
    root: x509.Certificate, ca_key: rsa.RSAPrivateKey
) -> None:
    # The public key and subject still match, but an attacker's private key
    # signed the bytes. Matching names/keys alone must never authorize issue.
    attacker = generate_rsa_private_key()
    forged = (
        x509.CertificateBuilder()
        .subject_name(root.subject)
        .issuer_name(root.issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(root.not_valid_before_utc)
        .not_valid_after(root.not_valid_after_utc)
        .add_extension(
            root.extensions.get_extension_for_class(x509.BasicConstraints).value,
            critical=True,
        )
        .add_extension(
            root.extensions.get_extension_for_class(x509.KeyUsage).value,
            critical=True,
        )
        .sign(attacker, hashes.SHA256())
    )
    with pytest.raises(CertificateError, match="signature"):
        issue_user_certificate(
            forged,
            ca_key,
            ca_key.public_key(),
            common_name="Mallory as Alice",
            organization="Demo University",
        )


def test_user_certificate_cannot_outlive_issuer(ca_key: rsa.RSAPrivateKey) -> None:
    short_root = create_root_ca(ca_key, valid_days=1)
    user = issue_user_certificate(
        short_root,
        ca_key,
        ca_key.public_key(),
        common_name="Alice",
        organization="Demo University",
        valid_days=365,
    )
    assert user.not_valid_after_utc == short_root.not_valid_after_utc


@pytest.mark.parametrize("days", [0, -1, 398, True, "365"])
def test_invalid_user_validity_is_rejected(
    root: x509.Certificate, ca_key: rsa.RSAPrivateKey, days: object
) -> None:
    with pytest.raises(CertificateError, match="Validity"):
        issue_user_certificate(
            root,
            ca_key,
            ca_key.public_key(),
            common_name="Alice",
            organization="Demo University",
            valid_days=days,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("common_name", "country"),
    [("", "NP"), ("Alice\nForged", "NP"), ("Alice", "NPL"), ("Alice", "np")],
)
def test_invalid_subject_rejected(
    root: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str,
    country: str,
) -> None:
    with pytest.raises(CertificateError):
        issue_user_certificate(
            root,
            ca_key,
            ca_key.public_key(),
            common_name=common_name,
            organization="Demo University",
            country=country,
        )


def test_non_rsa_and_weak_keys_rejected(
    root: x509.Certificate, ca_key: rsa.RSAPrivateKey
) -> None:
    ec_public = ec.generate_private_key(ec.SECP256R1()).public_key()
    weak_public = rsa.generate_private_key(65537, 2048).public_key()
    for public_key in (ec_public, weak_public):
        with pytest.raises(CertificateError, match="3072"):
            issue_user_certificate(
                root,
                ca_key,
                public_key,  # type: ignore[arg-type]
                common_name="Alice",
                organization="Demo University",
            )

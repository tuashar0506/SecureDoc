"""Package round trips and untrusted, mismatched, malformed or tampered input."""

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from securedoc.crypto.certificates import (
    certificate_fingerprint,
    create_root_ca,
    issue_user_certificate,
)
from securedoc.crypto.documents import (
    MAX_DOCUMENT_BYTES,
    MAX_PACKAGE_BYTES,
    open_document,
    seal_document,
)
from securedoc.crypto.key_manager import generate_rsa_private_key
from securedoc.security.trust import validate_certificate
from securedoc.utils.exceptions import CertificateError, DocumentError


@pytest.fixture(scope="module")
def identities() -> tuple[
    rsa.RSAPrivateKey,
    x509.Certificate,
    rsa.RSAPrivateKey,
    x509.Certificate,
    rsa.RSAPrivateKey,
    x509.Certificate,
]:
    root_key = generate_rsa_private_key()
    root = create_root_ca(root_key)
    alice_key = generate_rsa_private_key()
    alice = issue_user_certificate(
        root, root_key, alice_key.public_key(), common_name="Alice", organization="Demo"
    )
    bob_key = generate_rsa_private_key()
    bob = issue_user_certificate(
        root, root_key, bob_key.public_key(), common_name="Bob", organization="Demo"
    )
    return root_key, root, alice_key, alice, bob_key, bob


def _sealed(identities: tuple) -> bytes:
    _, root, alice_key, alice, _, bob = identities
    return seal_document(
        b"Confidential report\x00",
        "report.txt",
        alice_key,
        alice,
        bob,
        root,
        certificate_fingerprint(root),
    )


def test_round_trip_and_encrypted_content(identities: tuple) -> None:
    _, root, _, _, bob_key, bob = identities
    package = _sealed(identities)
    assert b"Confidential report" not in package
    assert open_document(
        package, bob_key, bob, root, certificate_fingerprint(root)
    ) == ("report.txt", b"Confidential report\x00")
    assert _sealed(identities) != package


def test_pinned_root_cannot_be_swapped(identities: tuple) -> None:
    _, root, _, alice, _, _ = identities
    with pytest.raises(CertificateError, match="fingerprint"):
        validate_certificate(alice, root, "0" * 64, purpose="sign")
    fake_root_key = generate_rsa_private_key()
    fake_root = create_root_ca(fake_root_key)
    with pytest.raises(DocumentError, match="certificate"):
        open_document(
            _sealed(identities),
            identities[4],
            identities[5],
            fake_root,
            certificate_fingerprint(root),
        )


def test_revoked_serial_is_rejected(identities: tuple) -> None:
    _, root, _, alice, _, _ = identities
    with pytest.raises(CertificateError, match="revocation"):
        validate_certificate(
            alice,
            root,
            certificate_fingerprint(root),
            purpose="sign",
            revoked_serials=frozenset({alice.serial_number}),
        )
    with pytest.raises(CertificateError, match="revocation"):
        validate_certificate(
            alice,
            root,
            certificate_fingerprint(root),
            purpose="sign",
            revoked_serials=frozenset({root.serial_number}),
        )


def test_wrong_recipient_and_signer_key(identities: tuple) -> None:
    _, root, alice_key, alice, bob_key, bob = identities
    with pytest.raises(DocumentError, match="recipient"):
        open_document(
            _sealed(identities), alice_key, bob, root, certificate_fingerprint(root)
        )
    with pytest.raises(DocumentError, match="signing key"):
        seal_document(
            b"x", "x.txt", bob_key, alice, bob, root, certificate_fingerprint(root)
        )


@pytest.mark.parametrize(
    "field",
    [
        "filename",
        "nonce",
        "recipient",
        "ciphertext",
        "signature",
        "wrapped_key",
        "sender",
    ],
)
def test_tampered_package_fails(identities: tuple, field: str) -> None:
    _, root, _, _, bob_key, bob = identities
    body = json.loads(_sealed(identities))
    body[field] = "different.txt" if field == "filename" else "AAAA"
    with pytest.raises(DocumentError):
        open_document(
            json.dumps(body).encode(), bob_key, bob, root, certificate_fingerprint(root)
        )


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"{", id="broken-json"),
        pytest.param(b"[]", id="array"),
        pytest.param(b"{}", id="missing-fields"),
        pytest.param(b"x" * (MAX_PACKAGE_BYTES + 1), id="oversized"),
    ],
)
def test_invalid_packages_fail(identities: tuple, payload: bytes) -> None:
    _, root, _, _, bob_key, bob = identities
    with pytest.raises(DocumentError):
        open_document(payload, bob_key, bob, root, certificate_fingerprint(root))


def test_duplicate_field_and_wrong_version_fail(identities: tuple) -> None:
    _, root, _, _, bob_key, bob = identities
    package = _sealed(identities)
    for bad in (
        package.replace(b'"version":1', b'"version":1,"version":1'),
        package.replace(b'"version":1', b'"version":true'),
    ):
        with pytest.raises(DocumentError):
            open_document(bad, bob_key, bob, root, certificate_fingerprint(root))


def test_gcm_rejects_modified_ciphertext_even_if_signer_resigns(
    identities: tuple,
) -> None:
    _, root, alice_key, _, bob_key, bob = identities
    body = json.loads(_sealed(identities))
    body["ciphertext"] = "AAAA"
    unsigned = {key: value for key, value in body.items() if key != "signature"}
    canonical = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    import base64

    body["signature"] = base64.b64encode(
        alice_key.sign(
            canonical,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    ).decode("ascii")
    with pytest.raises(DocumentError, match="authentication"):
        open_document(
            json.dumps(body).encode(),
            bob_key,
            bob,
            root,
            certificate_fingerprint(root),
        )


def test_document_size_is_bounded(identities: tuple) -> None:
    _, root, alice_key, alice, _, bob = identities
    with pytest.raises(DocumentError, match="16 MiB"):
        seal_document(
            b"x" * (MAX_DOCUMENT_BYTES + 1),
            "oversized.txt",
            alice_key,
            alice,
            bob,
            root,
            certificate_fingerprint(root),
        )


@pytest.mark.parametrize("filename", ["../bad", "a/b", "a\\b", "", "x\x00y", ".."])
def test_filename_validation(identities: tuple, filename: str) -> None:
    _, root, alice_key, alice, _, bob = identities
    with pytest.raises(DocumentError, match="filename"):
        seal_document(
            b"x", filename, alice_key, alice, bob, root, certificate_fingerprint(root)
        )

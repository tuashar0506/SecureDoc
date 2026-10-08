"""Bounded, signed and recipient-encrypted single-document .sdoc packages.

The signature covers the ciphertext and all authenticated metadata. The AES-GCM
tag authenticates the same metadata before any plaintext is returned.
"""

import base64
import binascii
import json
import os
from pathlib import PurePath

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securedoc.crypto.certificates import (
    certificate_fingerprint,
    load_certificate,
    serialize_certificate,
)
from securedoc.security.trust import validate_certificate
from securedoc.utils.exceptions import CertificateError, DocumentError

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 24 * 1024 * 1024
_FIELDS = frozenset(
    {
        "version",
        "filename",
        "sender",
        "recipient",
        "nonce",
        "wrapped_key",
        "ciphertext",
        "signature",
    }
)


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: object, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > (limit + 2) // 3 * 4 + 4:
        raise DocumentError("Invalid package encoding or field length.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DocumentError("Invalid base64 in document package.") from exc
    if len(raw) > limit or _encode(raw) != value:
        raise DocumentError("Non-canonical or oversized package field.")
    return raw


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DocumentError("Duplicate package field.")
        result[key] = value
    return result


def _check_filename(filename: object) -> str:
    """Accept a display basename, never a path supplied by a package."""
    if (
        not isinstance(filename, str)
        or not filename
        or len(filename) > 180
        or filename in (".", "..")
        or any(c in filename for c in "/\\\x00")
        or any(ord(c) < 32 or ord(c) == 127 for c in filename)
        or PurePath(filename).name != filename
    ):
        raise DocumentError("Document filename is unsafe.")
    return filename


def seal_document(
    data: bytes,
    filename: str,
    signer_key: rsa.RSAPrivateKey,
    signer: x509.Certificate,
    recipient: x509.Certificate,
    root: x509.Certificate,
    root_fingerprint: str,
) -> bytes:
    """Encrypt and sign in memory; output can be saved to a .sdoc file."""
    if not isinstance(data, bytes) or not 0 <= len(data) <= MAX_DOCUMENT_BYTES:
        raise DocumentError("Document exceeds the 16 MiB limit.")
    filename = _check_filename(filename)
    validate_certificate(signer, root, root_fingerprint, purpose="sign")
    validate_certificate(recipient, root, root_fingerprint, purpose="encrypt")
    if (
        not isinstance(signer_key, rsa.RSAPrivateKey)
        or signer_key.public_key().public_numbers()
        != signer.public_key().public_numbers()
    ):
        raise DocumentError("Signer certificate does not match the signing key.")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped = recipient.public_key().encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    header: dict[str, object] = {
        "version": 1,
        "filename": filename,
        "sender": _encode(serialize_certificate(signer)),
        "recipient": certificate_fingerprint(recipient),
        "nonce": _encode(nonce),
        "wrapped_key": _encode(wrapped),
    }
    body = dict(header)
    body["ciphertext"] = _encode(AESGCM(key).encrypt(nonce, data, _canonical(header)))
    signature = signer_key.sign(
        _canonical(body),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    body["signature"] = _encode(signature)
    result = _canonical(body)
    if len(result) > MAX_PACKAGE_BYTES:
        raise DocumentError("Document package exceeds the size limit.")
    return result


def open_document(
    package: bytes,
    recipient_key: rsa.RSAPrivateKey,
    recipient: x509.Certificate,
    root: x509.Certificate,
    root_fingerprint: str,
) -> tuple[str, bytes]:
    """Verify signer AND pinned root, then decrypt; return no unauthenticated data."""
    if not isinstance(package, bytes) or not 0 < len(package) <= MAX_PACKAGE_BYTES:
        raise DocumentError("Document package is empty or too large.")
    try:
        body = json.loads(package, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DocumentError("Malformed document package.") from exc
    if (
        not isinstance(body, dict)
        or body.keys() != _FIELDS
        or type(body["version"]) is not int
        or body["version"] != 1
    ):
        raise DocumentError("Unsupported document package fields or version.")
    filename = _check_filename(body["filename"])
    try:
        sender = load_certificate(_decode(body["sender"], 64 * 1024))
        validate_certificate(sender, root, root_fingerprint, purpose="sign")
        validate_certificate(recipient, root, root_fingerprint, purpose="encrypt")
    except CertificateError as exc:
        raise DocumentError("Document certificate or trusted root is invalid.") from exc
    if (
        not isinstance(recipient_key, rsa.RSAPrivateKey)
        or recipient_key.public_key().public_numbers()
        != recipient.public_key().public_numbers()
        or body["recipient"] != certificate_fingerprint(recipient)
    ):
        raise DocumentError(
            "Document is not addressed to this recipient key and certificate."
        )
    nonce = _decode(body["nonce"], 12)
    wrapped = _decode(body["wrapped_key"], 1024)
    ciphertext = _decode(body["ciphertext"], MAX_DOCUMENT_BYTES + 16)
    signature = _decode(body["signature"], 1024)
    if (
        len(nonce) != 12
        or len(wrapped) != recipient_key.key_size // 8
        or len(signature) != sender.public_key().key_size // 8
    ):
        raise DocumentError("Invalid cryptographic field size.")
    signed = {k: v for k, v in body.items() if k != "signature"}
    try:
        sender.public_key().verify(
            signature,
            _canonical(signed),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise DocumentError("Document signature is invalid.") from exc
    try:
        key = recipient_key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        if len(key) != 32:
            raise DocumentError("Invalid document encryption key.")
        header = {k: v for k, v in signed.items() if k != "ciphertext"}
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _canonical(header))
    except (ValueError, InvalidTag) as exc:
        raise DocumentError("Document authentication or decryption failed.") from exc
    if len(plaintext) > MAX_DOCUMENT_BYTES:
        raise DocumentError("Document exceeds the 16 MiB limit.")
    return filename, plaintext

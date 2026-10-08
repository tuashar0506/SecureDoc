"""File-based application workflows shared by CLI and desktop interface."""

import hmac
import os
from pathlib import Path

from cryptography import x509

from securedoc.crypto.certificates import (
    MAX_CERTIFICATE_BYTES,
    certificate_fingerprint,
    create_root_ca,
    issue_user_certificate,
    load_certificate,
    serialize_certificate,
)
from securedoc.crypto.documents import (
    MAX_DOCUMENT_BYTES,
    MAX_PACKAGE_BYTES,
    open_document,
    seal_document,
)
from securedoc.crypto.key_manager import (
    generate_rsa_private_key,
    load_private_key,
    save_private_key,
)
from securedoc.utils.exceptions import CertificateError, DocumentError


def _read(path: Path, maximum: int) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise DocumentError("Input file exceeds the supported size limit.")
    return data


def _save_new(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write exclusively; never follow an existing destination or overwrite it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(Path(path), flags, mode)
    except FileExistsError as exc:
        raise DocumentError("Output already exists; choose a new file.") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        # A partial file may exist; do not overwrite or silently remove it.
        raise


def read_certificate(path: Path) -> x509.Certificate:
    """Read only bounded, public certificate data from disk."""
    return load_certificate(_read(path, MAX_CERTIFICATE_BYTES))


def root_fingerprint(path: Path) -> str:
    """Print/compare this value out of band before trusting this CA."""
    return certificate_fingerprint(read_certificate(path))


def _pinned_root(path: Path, pin: str) -> x509.Certificate:
    root = read_certificate(path)
    if (
        not isinstance(pin, str)
        or len(pin) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in pin)
        or not hmac.compare_digest(certificate_fingerprint(root), pin.upper())
    ):
        raise CertificateError("Root certificate does not match your trusted pin.")
    return root


def initialize_ca(key_path: Path, cert_path: Path, password: str) -> str:
    """Create an encrypted root key and a public certificate; return its pin."""
    if Path(key_path) == Path(cert_path) or any(
        Path(path).exists() for path in (key_path, cert_path)
    ):
        raise DocumentError("Choose two different, unused output paths.")
    key = generate_rsa_private_key()
    cert = create_root_ca(key)
    save_private_key(key, Path(key_path), password)
    _save_new(Path(cert_path), serialize_certificate(cert), mode=0o644)
    return certificate_fingerprint(cert)


def issue_identity(
    root_key_path: Path,
    root_cert_path: Path,
    root_pin: str,
    root_password: str,
    key_path: Path,
    cert_path: Path,
    password: str,
    *,
    name: str,
    organization: str,
) -> None:
    """Issue a local end-entity certificate with a separate encrypted key."""
    if Path(key_path) == Path(cert_path) or any(
        Path(path).exists() for path in (key_path, cert_path)
    ):
        raise DocumentError("Choose two different, unused output paths.")
    root = _pinned_root(root_cert_path, root_pin)
    root_key = load_private_key(root_key_path, root_password)
    key = generate_rsa_private_key()
    certificate = issue_user_certificate(
        root, root_key, key.public_key(), common_name=name, organization=organization
    )
    save_private_key(key, Path(key_path), password)
    _save_new(Path(cert_path), serialize_certificate(certificate), mode=0o644)


def protect_file(
    source: Path,
    destination: Path,
    signer_key_path: Path,
    signer_cert_path: Path,
    recipient_cert_path: Path,
    root_cert_path: Path,
    root_pin: str,
    password: str,
) -> None:
    """Save authenticated, encrypted .sdoc; source is read but never changed."""
    if Path(destination).suffix.lower() != ".sdoc":
        raise DocumentError("Encrypted output must end with .sdoc.")
    root = _pinned_root(root_cert_path, root_pin)
    signer = read_certificate(signer_cert_path)
    recipient = read_certificate(recipient_cert_path)
    signer_key = load_private_key(signer_key_path, password)
    package = seal_document(
        _read(source, MAX_DOCUMENT_BYTES),
        Path(source).name,
        signer_key,
        signer,
        recipient,
        root,
        root_pin,
    )
    _save_new(destination, package)


def recover_file(
    source: Path,
    destination: Path,
    recipient_key_path: Path,
    recipient_cert_path: Path,
    root_cert_path: Path,
    root_pin: str,
    password: str,
) -> str:
    """Save plaintext only after certificate, signature and GCM checks succeed."""
    root = _pinned_root(root_cert_path, root_pin)
    recipient = read_certificate(recipient_cert_path)
    recipient_key = load_private_key(recipient_key_path, password)
    name, data = open_document(
        _read(source, MAX_PACKAGE_BYTES), recipient_key, recipient, root, root_pin
    )
    _save_new(destination, data)
    return name

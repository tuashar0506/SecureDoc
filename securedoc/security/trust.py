"""Explicit, pinned-root X.509 validation (not real-world identity proof)."""

import hmac
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

from securedoc.crypto.certificates import certificate_fingerprint
from securedoc.utils.exceptions import CertificateError


def validate_certificate(
    certificate: x509.Certificate,
    root: x509.Certificate,
    expected_root_fingerprint: str,
    *,
    purpose: str,
    revoked_serials: frozenset[int] = frozenset(),
) -> None:
    """Validate a direct-issue end entity against a manually pinned local root.

    The fingerprint MUST come from an independent trusted channel. No system
    store, online revocation, identity vetting, or intermediates are supported.
    """
    if purpose not in ("sign", "encrypt"):
        raise CertificateError("Unsupported certificate purpose.")
    if (
        not isinstance(expected_root_fingerprint, str)
        or len(expected_root_fingerprint) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_root_fingerprint)
        or not hmac.compare_digest(
            certificate_fingerprint(root), expected_root_fingerprint.upper()
        )
    ):
        raise CertificateError("Root fingerprint does not match the trusted pin.")

    now = datetime.now(UTC)
    for item in (root, certificate):
        if not item.not_valid_before_utc <= now < item.not_valid_after_utc:
            raise CertificateError("Certificate is not currently valid.")
        key = item.public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
            raise CertificateError("Certificate requires an RSA-3072 public key.")
        if item.version != x509.Version.v3:
            raise CertificateError("Only X.509 v3 certificates are accepted.")

    try:
        root_constraints = root.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        root_usage = root.extensions.get_extension_for_class(x509.KeyUsage)
        end_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        end_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        root_ski = root.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        end_aki = certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        if (
            root.subject != root.issuer
            or not root_constraints.critical
            or not root_constraints.value.ca
            or root_constraints.value.path_length != 0
            or not root_usage.critical
            or not root_usage.value.key_cert_sign
            or not end_constraints.critical
            or end_constraints.value.ca
            or not end_usage.critical
            or certificate.issuer != root.subject
            or end_aki.key_identifier != root_ski.digest
            or certificate.serial_number in revoked_serials
            or root.serial_number in revoked_serials
        ):
            raise CertificateError("Certificate chain, usage or revocation is invalid.")
        if purpose == "sign" and not end_usage.value.digital_signature:
            raise CertificateError("Certificate is not allowed to sign documents.")
        if purpose == "encrypt" and not end_usage.value.key_encipherment:
            raise CertificateError("Certificate is not allowed to encrypt documents.")
        allowed_root = {
            x509.BasicConstraints.oid,
            x509.KeyUsage.oid,
            x509.SubjectKeyIdentifier.oid,
        }
        allowed_end = allowed_root | {x509.AuthorityKeyIdentifier.oid}
        for item, allowed in ((root, allowed_root), (certificate, allowed_end)):
            if any(ext.critical and ext.oid not in allowed for ext in item.extensions):
                raise CertificateError("Unknown critical certificate extension.")
        root.verify_directly_issued_by(root)
        certificate.verify_directly_issued_by(root)
    except (
        x509.ExtensionNotFound,
        InvalidSignature,
        UnsupportedAlgorithm,
        ValueError,
    ) as exc:
        raise CertificateError(
            "Certificate signature or required extension is invalid."
        ) from exc

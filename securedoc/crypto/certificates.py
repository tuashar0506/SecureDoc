"""Issue local X.509 certificates; issuance alone is not a trust decision."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from securedoc.utils.exceptions import CertificateError

ROOT_COMMON_NAME = "SecureDoc Root CA"
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_ROOT_DAYS = 3650
MAX_USER_DAYS = 397
_CLOCK_SKEW = timedelta(minutes=5)


def create_root_ca(
    private_key: rsa.RSAPrivateKey,
    *,
    organization: str = "SecureDoc Nepal",
    country: str = "NP",
    valid_days: int = MAX_ROOT_DAYS,
) -> x509.Certificate:
    """Create a self-signed, non-intermediate, local document-issuing root."""
    _require_rsa_key(private_key)
    _check_valid_days(valid_days, MAX_ROOT_DAYS)
    name = _name(ROOT_COMMON_NAME, organization, country)
    public_key = private_key.public_key()
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )
    return builder.sign(private_key, hashes.SHA256(), rsa_padding=_pss_padding())


def issue_user_certificate(
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    *,
    common_name: str,
    organization: str,
    country: str = "NP",
    valid_days: int = 365,
) -> x509.Certificate:
    """Issue an RSA document certificate, never extending past the CA expiry.

    This proves that the supplied CA key signed the result. It does not decide
    whether another application should trust this root or the issued identity.
    """
    _require_issuing_ca(ca_certificate, ca_private_key)
    _require_rsa_key(public_key)
    _check_valid_days(valid_days, MAX_USER_DAYS)
    subject = _name(common_name, organization, country)
    now = datetime.now(UTC)
    expires = min(now + timedelta(days=valid_days), ca_certificate.not_valid_after_utc)
    if expires <= now:
        raise CertificateError("CA certificate has expired; cannot issue certificates.")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_user_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_private_key.public_key()
            ),
            critical=False,
        )
    )
    return builder.sign(ca_private_key, hashes.SHA256(), rsa_padding=_pss_padding())


def serialize_certificate(certificate: x509.Certificate) -> bytes:
    """Encode an X.509 certificate as public PEM, without a private key."""
    return certificate.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem: bytes) -> x509.Certificate:
    """Parse a bounded public PEM; parsing does not establish trust."""
    if not isinstance(pem, bytes) or not 0 < len(pem) <= MAX_CERTIFICATE_BYTES:
        raise CertificateError("Certificate PEM is empty or too large.")
    pem = pem.replace(b"\r\n", b"\n")
    if (
        b"\r" in pem
        or not pem.startswith(b"-----BEGIN CERTIFICATE-----\n")
        or not pem.rstrip(b"\n").endswith(b"-----END CERTIFICATE-----")
        or pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or pem.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise CertificateError("Expected exactly one X.509 certificate PEM.")
    try:
        return x509.load_pem_x509_certificate(pem)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise CertificateError("Invalid X.509 certificate PEM.") from exc


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint of the complete DER certificate."""
    return certificate.fingerprint(hashes.SHA256()).hex().upper()


def _require_issuing_ca(
    certificate: x509.Certificate, private_key: rsa.RSAPrivateKey
) -> None:
    """Reject a mismatched, expired, or non-CA signing certificate."""
    _require_rsa_key(private_key)
    now = datetime.now(UTC)
    if (
        certificate.subject != certificate.issuer
        or certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
        or not isinstance(certificate.public_key(), rsa.RSAPublicKey)
        or certificate.public_key().public_numbers()
        != private_key.public_key().public_numbers()
    ):
        raise CertificateError("CA identity, key, or validity is incorrect.")
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if (
            not constraints.ca
            or constraints.path_length != 0
            or not usage.key_cert_sign
        ):
            raise CertificateError("Certificate cannot issue end-entity certificates.")
        certificate.verify_directly_issued_by(certificate)
    except (
        x509.ExtensionNotFound,
        InvalidSignature,
        UnsupportedAlgorithm,
        ValueError,
    ) as exc:
        raise CertificateError("Invalid CA certificate or signature.") from exc


def _require_rsa_key(key: object) -> None:
    if (
        not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))
        or key.key_size < 3072
    ):
        raise CertificateError("A 3072-bit or stronger RSA key is required.")


def _check_valid_days(days: int, maximum: int) -> None:
    if type(days) is not int or not 1 <= days <= maximum:
        raise CertificateError(f"Validity must be between 1 and {maximum} days.")


def _name(common_name: str, organization: str, country: str) -> x509.Name:
    for value in (common_name, organization):
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise CertificateError("Subject name must be nonempty, safe text.")
    if (
        not isinstance(country, str)
        or len(country) != 2
        or not country.isascii()
        or not country.isalpha()
        or country != country.upper()
    ):
        raise CertificateError("Country must be two uppercase ASCII letters.")
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _pss_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _ca_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _user_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

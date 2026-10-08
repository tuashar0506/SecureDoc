"""Safe application errors for key-management operations."""


class SecureDocError(Exception):
    """Base class for errors that may be shown to an application user."""


class KeyManagementError(SecureDocError):
    """Key creation, parsing, or storage failed."""


class IncorrectPasswordError(KeyManagementError):
    """An encrypted private key could not be unlocked with this password."""


class CertificateError(SecureDocError):
    """Certificate creation, parsing, or issuance was rejected."""


class DocumentError(SecureDocError):
    """A document or package failed validation or authentication."""

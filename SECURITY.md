# Security policy

**Status:** RSA key storage and local X.509 issuance are implemented. SecureDoc
Nepal is coursework, not audited or production-ready. Trust validation,
revocation and document workflows are not implemented. Do not use it for
sensitive documents or real-world identity verification.

## Reporting a vulnerability

If the repository's **Security → Advisories → Report a vulnerability** option
is available on GitHub, use it to report privately. Otherwise, contact the
maintainer through a private channel before publishing exploit details. Do not
post passwords, private keys, real documents or sensitive personal information
in a public issue. No response time or bounty is promised.

## Scope and limitations

Future cryptographic features will need tests and independent review. A valid
signature alone cannot establish real-world identity or legal non-repudiation.
Local CA trust, revocation database integrity, secure endpoints, strong
passwords and correct clock settings will all matter. A compromised CA key
or endpoint can defeat the intended trust model. Static RSA file encryption
does not provide forward secrecy. See the README for the current feature status.

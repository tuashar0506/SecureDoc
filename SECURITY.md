# Security policy

**Status:** Local signed/encrypted `.sdoc` workflows and pinned direct-issuer
validation are implemented. Revocation checks, real-world identity vetting,
GUI display testing on this host, and native package verification are not.
SecureDoc Nepal is coursework, not audited or production-ready. Do not use it
for sensitive documents or real-world identity verification.

## Reporting a vulnerability

If the repository's **Security → Advisories → Report a vulnerability** option
is available on GitHub, use it to report privately. Otherwise, contact the
maintainer through a private channel before publishing exploit details. Do not
post passwords, private keys, real documents or sensitive personal information
in a public issue. No response time or bounty is promised.

## Scope and limitations

Local root pinning checks the key and chain only; there is no automatic
revocation enforcement. A valid signature alone cannot establish real-world
identity or legal non-repudiation. Secure endpoints, strong passwords,
correct clock settings and CA key custody all matter. A compromised CA key
or endpoint can defeat the intended trust model. Static RSA file encryption
does not provide forward secrecy. See the README for actual feature status.

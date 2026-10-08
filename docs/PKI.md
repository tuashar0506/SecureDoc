# Local X.509 PKI: issuance and pinned-chain validation

**Status:** Real root and user-certificate issuance is implemented in
`securedoc/crypto/certificates.py`. Direct-issuer chain, date, signature and
purpose checks under a manually pinned root are in `securedoc/security/trust.py`.
Revocation enforcement and independent identity verification are **not**
implemented. The Tk interface exists but its display behavior is not tested
in this Linux Python environment. Do not use generated certificates as evidence
of real-world identity until an explicit, documented identity-verification
process and trust decision exist.

## What is built

`create_root_ca()` takes an RSA-3072-or-stronger private key held in memory and
creates a self-signed X.509 certificate. Its issuer and subject are the same;
critical Basic Constraints mark it as a CA with no intermediate CA children.
Critical Key Usage allows certificate and CRL signing. The SHA-256 signature is
RSA-PSS. The root is **not** trusted by an operating system merely because it
is self-signed: the application must explicitly select and protect an authentic
root certificate using a fingerprint confirmed through a separate channel.

`issue_user_certificate()` checks that the presented root's public key matches
the signing private key, its self-signature verifies, it is currently valid,
and CA extensions authorize issuance. It generates a cryptographically random
positive serial number, a subject (country, organization, common name), SHA-256
subject/authority key identifiers and critical end-entity key usage suitable
for signing and RSA key wrapping. Its expiry never exceeds the root's expiry.
The password-encrypted CA private-key **storage** belongs to the existing
`key_manager.py` API; no unencrypted CA key should be written to disk.

`serialize_certificate()` returns public PEM, `load_certificate()` only parses
a bounded PEM, and `certificate_fingerprint()` returns a SHA-256 fingerprint.
**Parsing and fingerprinting never mean trusted.** The current direct-issuer
validator checks a caller-provided SHA-256 root pin, self-signature, issuer,
signature, dates, RSA strength and key usage. A caller may pass revoked serials
in memory, but no persistent revocation store or CRL is enforced. Therefore
validation alone does not establish current non-revocation or real-world identity.

## In-memory learning example

After activating `.venv`, run this from the repository root. It creates **no
files** and prints no private keys:

```sh
python examples/pki_demo.py
```

Successful output starts `X.509 issuance signature verifies; trust is NOT
established.`, followed by 64 hexadecimal characters. This checks issuance
under the generated root, **not**
whether a recipient has decided to trust that root or Alice's real identity.

## Limits and threats

- This is an offline local CA, not a Nepalese government or public CA.
- Anyone can create their own self-signed root. A forged root must not be
  trusted just because its self-signature is valid.
- Issuance does not verify the identity of the named person or organization.
- Compromise of the CA private key defeats this CA's identity assertions.
- A weak private-key password reduces protection even when stored encrypted.
- There is no CRL, persistent revocation store, intermediate chain builder,
  or identity database. The GUI has not been display-tested on all platforms.
- Generated certificates in tests remain in memory. No private-key PEM or
  generated certificates are committed as fixtures.

Run `python -m pytest tests/test_certificates.py -v` to exercise genuine X.509
issuance and rejected CA/key/subject inputs. Do not interpret passing issuance
tests as proof of real-world identity verification.

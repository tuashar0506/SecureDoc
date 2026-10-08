# SecureDoc Nepal — repository instructions

## Scope and current state

This is ST6051CEM Practical Cryptography coursework, not an audited product.
Read `README.md` and `git status --short --branch` before editing. The working
tree may contain staged, uncommitted work: never reset, discard, or overwrite it.
Do not call planned features implemented merely because a package directory
exists. Check executable code and meaningful tests first.

## Security rules

- Use maintained `cryptography` APIs. Do not implement ciphers or PKI with
  simulated JSON certificates; do not weaken certificate verification for tests.
- Never save plaintext private keys, passwords, AES keys, shared secrets, or
  real documents to Git. Tests must use generated identities and temporary
  directories; never persist a real unencrypted private key, even in tests.
- Keep cryptographic signature validity separate from trusted identity,
  certificate expiry, and revocation. Issuance is not trust validation.
- Treat `.sdoc` and certificates as untrusted input. Bound size and validate
  formats before processing; reject authentication failures.
- Do not claim forward secrecy for static RSA encryption or legal proof of
  identity solely from a signature.
- Do not commit `.venv`, build artifacts, runtime keys, certificates, audit
  logs, passwords, or tokens. Never log secret material.

## Structure and development workflow

- `securedoc/crypto/`: focused cryptographic operations; `security/`:
  trust/revocation/replay controls (not yet implemented); `services/`: future
  application workflows; `gui/`: future UI, only after the core is tested.
- Add tests for successful use *and* wrong password, tampering, forged input,
  wrong identity, and malformed data where relevant.
- Use `pathlib` and, when user data storage is implemented, `platformdirs`.
  Do not store mutable user data beside a packaged executable.
- Update the README's implemented/planned list when functionality changes.
  Diagrams, screenshots, CI, and release claims must match actual results.
- On Fish: `source .venv/bin/activate.fish`; install project dependencies only
  in `.venv`, using `python -m pip install -r requirements.txt`.
- Before proposing a commit run `python -m pytest -v`,
  `python -m ruff check .`, `python -m black --check .`, `git status`,
  `git diff`, and `git diff --staged`. Inspect the staged list for secrets.
- Do not push, tag, or publish a release unless explicitly authorized. GitHub
  workflow configuration is not evidence of a successful GitHub Actions run.

## Phase boundaries

Current core work builds on password-encrypted RSA key storage and X.509
issuance. Next steps are certificate trust/expiry, RSA-PSS document signatures,
AES-GCM, hybrid document encryption, validated `.sdoc` packages,
revocation/replay, and optional X25519.
Only then should services, GUI, Security Lab, native packaging, and releases
claim to provide those workflows. Never ship a status-only CLI as a finished
desktop security application.

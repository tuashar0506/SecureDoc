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
  pinned-root validation (revocation/replay remain unimplemented); `services/`:
  CLI/GUI shared workflows; `gui/`: desktop Tk interface, native display
  behavior not verified until a real native runner launches it.
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
- Native builds are experimental until successfully built and GUI-launched on
  every target OS. Release workflow may prepare unpublished drafts only; do
  not publish as a finished security product or upload runtime secrets.

## Phase boundaries

Implemented core: RSA key storage, X.509 issuance, pinned-root direct-chain
and expiry validation, signed and encrypted single-recipient `.sdoc` files,
CLI and native Tk GUI. Pending: local revocation enforcement, GUI/native build
verification on all platforms, optional X25519, Security Lab and any claims
of production security. No authenticated network request workflow exists, so
request replay protection is not applicable to the present offline file tool.

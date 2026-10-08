# SecureDoc Nepal

**Secure document sharing, signing, encryption and verification — under development.**

Coursework project for **ST6051CEM Practical Cryptography**. This repository is
currently a project foundation, not a usable security product. Do not use it to
protect real documents or secrets. Security claims below describe the intended
design, **not completed functionality**.

## Status and features

| Status | Capability |
| --- | --- |
| Implemented | Foundation, Docker development/test image, encrypted RSA-3072 keys, local X.509 root and user-certificate issuance |
| In progress | Cryptographic core and automated security tests |
| Planned | Multiple-identity management and certificate trust, expiry and revocation validation |
| Planned | RSA-PSS/SHA-256 signing, AES-256-GCM and RSA-OAEP hybrid encryption |
| Planned | Safe `.sdoc` packages, revocation checks, authenticated-request replay protection |
| Planned | Optional X25519/HKDF exchange, service layer, GUI, Security Lab and audit logging |

There is **no** document encryption, signing, trust validation, identity manager,
or GUI yet. Creating a CA certificate does **not** make it trusted.

## Security goals and design (planned)

- **Confidentiality:** encrypt each document under a new random AES-256 key;
  protect that key for the intended recipient with RSA-OAEP/SHA-256.
- **Integrity:** AES-GCM authenticates encrypted data; RSA-PSS/SHA-256 signs
  document data. A hash alone is not encryption or proof of authorship.
- **Authentication:** verify the signature *and* the signer certificate's chain,
  validity interval, trusted root and local revocation status before trusting
  an identity. A cryptographically valid signature does not imply trust.
- **Non-repudiation:** a signature links data to possession of a private key;
  it cannot prove who physically operated the device, rule out key compromise,
  or by itself establish legal non-repudiation.
- **Replay resistance:** only authenticated requests where repeating an
  operation matters will use a message ID, timestamp and persistent replay
  tracking. Merely opening a document twice is not an attack.
- **Optional forward secrecy:** an advanced X25519/HKDF exchange will be
  separately specified and tested. Static RSA-OAEP file encryption does
  **not** provide forward secrecy; ephemeral keys alone do not erase stored
  plaintext or protect compromised endpoints.

Cryptography will use the established Python `cryptography` library rather than
home-grown primitives. Private keys must be encrypted at rest with a password;
the implemented PEM format and password rules are documented below.

## Architecture

`securedoc/crypto/` will hold primitives and certificate issuance;
`securedoc/security/` will handle validation, revocation and replay controls;
`securedoc/models/` will validate package data; `securedoc/services/` will
coordinate workflows; `securedoc/gui/` will contain the future interface;
`securedoc/utils/` will contain safe, shared helpers. Tests live in `tests/`.
The entry point `app.py` currently prints a development status message only.
`securedoc/crypto/key_manager.py` implements RSA-3072 key generation and
encrypted key storage, independently of a GUI or identity database.
`securedoc/crypto/certificates.py` creates and issues real X.509 certificates;
see [the PKI design notes](docs/PKI.md) for the implemented checks and limits.

## Key management (implemented library API)

`generate_rsa_private_key()` generates an RSA-3072 private key; its public
counterpart is obtained using `.public_key()`. `save_private_key()` writes an
encrypted PKCS#8 PEM using `cryptography`'s `BestAvailableEncryption`. The
password must contain at least 12 characters; length alone does not guarantee
a strong password. Only you can supply that password; it is never saved.
`load_private_key()` unlocks the PEM. `save_public_key()` and
`load_public_key()` work with a public PEM, which contains no private material.
New files are created without overwriting existing files; on POSIX systems,
private-key files are created with owner-only permissions (`0600`). Windows
file ACLs depend on the user's operating-system account and must be checked
before using real keys. Avoid putting real private keys in this coursework
repository, even in ignored directories. Key generation and saving are not
connected to `app.py` yet; run `python -m pytest tests/test_keys.py -v` to
exercise both successful and failure cases.

## Install and run (foundation)

Use an isolated environment; do not install project dependencies globally.
Python 3.11+ is configured. Key-management tests passed in a Linux Docker
image with Python 3.14.8; Python 3.14.7 on CachyOS and GUI compatibility
still need validation. Commands below start in the project directory.

### Linux (Fish shell)

```fish
cd ~/securedoc-nepal
if not test -d .venv
    virtualenv .venv
end
source .venv/bin/activate.fish
python -m pip install -r requirements.txt
python app.py
```

If `.venv` already exists, **do not recreate it**: just activate it. For Bash,
use `source .venv/bin/activate` instead. Check `which python` points into `.venv`.

### Docker development/test option

Docker is optional. It provides a repeatable **CLI test environment**, not a
working security product or a GUI. Run from the repository root with a trusted
Docker daemon; image builds download Python packages from package repositories.
The default image uses Python 3.13. Key-management tests have also passed in
a Python 3.14.8 Linux Docker image; this does not prove GUI or native Windows
and macOS compatibility.

```sh
docker build -t securedoc-nepal:dev .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m --cap-drop ALL --security-opt no-new-privileges securedoc-nepal:dev
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m --cap-drop ALL --security-opt no-new-privileges securedoc-nepal:dev python -m pytest -p no:cacheprovider -v
```

The first `docker run` prints the same status as `python app.py`;
the second should pass the foundation and key-management tests. The image
runs as a non-root user; project dependencies live inside its `/opt/venv`.
`.dockerignore` excludes local keys, documents, `.venv` and Git history from
the build context.
Do not mount host keys, private documents or the Docker socket into the image.
Docker isolation is not a replacement for cryptographic security, and access
to the Docker daemon is security-sensitive. A GUI-in-Docker workflow is not
provided or tested.

### Windows (PowerShell)

```powershell
cd path\to\securedoc-nepal
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

### macOS (default shell)

```sh
cd /path/to/securedoc-nepal
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

The expected current output is `SecureDoc Nepal: key management ready; document
workflows are not implemented yet.` This is **not** an encryption test.

## Tests and development checks

Once the development requirements are installed into `.venv`:

```sh
python -m pytest
python -m pytest -v
python -m pytest --cov=securedoc --cov-report=term-missing
python -m ruff check .
python -m black --check .
```

At this stage, foundation, key-management and X.509 issuance tests exist;
coverage does **not** establish cryptographic security. CI across Ubuntu,
Windows and macOS is planned; no CI result is claimed yet.

## Security Lab (planned)

The eventual GUI will demonstrate valid and tampered signatures, wrong keys,
AES-GCM authentication failures, untrusted/forged/expired/revoked certificates
and replayed authenticated requests. Each demonstration will explain the
attack, control and observed result; none is available today.

## Project structure

```text
app.py                 # Honest, runnable foundation placeholder
Dockerfile             # Optional non-root CLI development/test image
.dockerignore          # Excludes local environments and secrets from build context
securedoc/             # key_manager.py and future crypto/security/services modules
tests/                 # Foundation and key-management tests; more to follow
docs/                  # Future architecture and threat-model details
examples/              # Future non-sensitive examples
screenshots/           # Future real GUI screenshots
.github/workflows/     # Future cross-platform CI
```

## Threat model summary

An attacker may obtain or alter document packages, replace documents, replay
captured authenticated operations, generate keys and present self-signed or
untrusted certificates. The future implementation must check trust independently
of signature validity. It cannot protect an already compromised endpoint, a
stolen unlocked key, a compromised trusted CA or weak private-key passwords.
Local revocation will depend on the availability and integrity of the local
revocation store; it is not an Internet-wide revocation service.

## Intended real-world use cases (not yet supported)

1. **Nepalese university verification** — Problem: verifying transcripts,
   recommendations and certificates. Threat: document substitution or false
   authorship. Control: CA-validated RSA-PSS signature. Result: detect changes
   and link a signature to a certified key. Limitation: the CA's identity checks
   and the university's issuance process are outside cryptographic proof.
2. **Business contract exchange** — Problem: sending a confidential contract to
   a partner. Threat: interception and alteration. Control: recipient-bound
   hybrid encryption and separate signer verification. Result: only the holder
   of the intended private key can decrypt, assuming uncompromised keys;
   unauthorized changes fail authentication. Limitation: recipient compromise,
   metadata exposure and legal enforceability are not solved by encryption.
3. **Organizational documents** — Problem: exchanging financial, legal and
   internal reports. Threat: an outsider forges a sender certificate or replays
   a request. Control: trusted-root validation, revocation and request replay
   tracking. Result: reject untrusted identities and already-seen authenticated
   requests. Limitation: offline copies and compromised trusted devices remain
   outside these controls.

## Known limitations

- Only key generation, PEM key storage and X.509 certificate issuance work;
  no document security workflow exists yet. This is not production-ready.
- Certificate verification, revocation, replay tracking and forward secrecy are
  design goals, not implemented guarantees.
- No GUI or installer; Python 3.14/CustomTkinter and cross-platform behavior
  have not been confirmed outside the tested Docker key-management workflow.
- File names, sizes and interaction metadata may still be observable in a
  future design unless specifically protected.

## Roadmap

1. Key storage and X.509 issuance (implemented); trust validation (planned).
2. Signatures, AES-GCM, hybrid encryption and validated `.sdoc` packages.
3. Revocation, replay protection and optional X25519 exchange.
4. Service layer, GUI and Security Lab; audit logs.
5. Cross-platform CI, documentation, diagrams, real screenshots and packaging.

## Screenshots

Not available: no GUI has been implemented. Real screenshots will be added
after the interface is built and tested.

## Contributing, security and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and
[SECURITY.md](SECURITY.md) for private security reporting and limitations.
Licensed under the [MIT License](LICENSE). Do not commit keys, credentials,
private documents or real certificate authority material.

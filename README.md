# SecureDoc Nepal

**Educational document signing and encryption with a CLI and Qt desktop GUI.**

ST6051CEM Practical Cryptography coursework, **not audited or suitable for real
secrets**. Windows/macOS compatibility and packaged GUI launches must be checked
on native hardware before relying on them; a workflow file is not a test result.

## Feature status

| Status | Capability |
| --- | --- |
| Implemented and locally tested | Password-encrypted RSA-3072 keys; X.509 local root and user issuance; SHA-256 root fingerprint pinning and direct-issuer/validity/key-usage checks; RSA-PSS/SHA-256 package signatures; fresh AES-256-GCM document encryption and RSA-OAEP/SHA-256 recipient key wrapping; bounded `.sdoc` parser; exclusive file writes; shared CLI/file workflows |
| Implemented, native display unverified on this host | PySide6/Qt Widgets desktop interface with native System mode, explicit light/dark modes, bundled Lucide/Tabler/Heroicons SVGs, and the same shared workflows; Wayland is preferred in detected Wayland sessions |
| Locally checked offscreen, native display unverified | Linux PyInstaller GUI and CLI bundles built and smoke-tested with temporary host libraries outside the repository; Windows/macOS builds and full native GUI workflows still need verification; tag-triggered **draft prereleases only** |
| Not implemented | Online identity verification, persistent revocation/CRL enforcement, authenticated network request replay tracking, X25519 forward secrecy, multi-recipient encryption, native code signing/notarization, Security Lab |

Certificate issuance, a valid document signature, and a selected root fingerprint
**do not prove** who actually used a key, that a root was honestly distributed,
or that a certificate has not been revoked. No legal non-repudiation is claimed.
Static RSA file encryption does **not** provide forward secrecy. The format is
one signed and encrypted document for one recipient; metadata (original filename,
sender certificate and recipient fingerprint) is **visible** in the package,
though signed and authenticated. Do not commit generated keys, certificates,
documents, `.sdoc` files or audit data.

## Installation

Use Python 3.11+; `requirements.txt` installs PySide6-Essentials (Qt Widgets)
for the GUI. Linux needs working Qt display libraries and an X11 or Wayland
desktop session. The CLI itself does not need a display. In Fish:

```fish
cd ~/securedoc-nepal
source .venv/bin/activate.fish  # if the environment already exists
python -m pip install -r requirements.txt
python app.py --help
python app.py gui
```

If there is no `.venv`, create one with `python3 -m venv .venv` first. For Bash,
use `source .venv/bin/activate`; for Windows PowerShell, use
`.\.venv\Scripts\Activate.ps1`. `python app.py` also launches the GUI.
On Linux Wayland sessions, the GUI prefers Qt's Wayland plugin (with XCB as a
fallback if the plugin is unavailable). It respects an existing
`QT_QPA_PLATFORM` setting. `QT_QPA_PLATFORM=xcb python app.py gui` explicitly
uses XWayland if needed. Qt display/library errors mean the host needs native
Qt runtime libraries and a working display. There is no configured application data
directory or auto-saved password: file paths are explicitly chosen by users.

## CLI quick start

Every key password is entered interactively with `getpass`; **never** put it in
shell arguments or scripts. Save files outside the repository, for example in
your home directory. The commands below assume the shell is in a directory for
**new, unused** output paths. Replace `PIN` with a 64-character hex SHA-256
root fingerprint confirmed through a trusted *independent* channel.

```sh
python app.py init-ca --key root.key --cert root.pem
python app.py fingerprint root.pem
python app.py issue --root-key root.key --root-cert root.pem --root-pin PIN --name Alice --organization Demo --key alice.key --cert alice.pem
python app.py issue --root-key root.key --root-cert root.pem --root-pin PIN --name Bob --organization Demo --key bob.key --cert bob.pem
python app.py seal report.txt report.sdoc --signer-key alice.key --signer-cert alice.pem --recipient-cert bob.pem --root-cert root.pem --root-pin PIN
python app.py open report.sdoc restored.txt --recipient-key bob.key --recipient-cert bob.pem --root-cert root.pem --root-pin PIN
```

Use `python app.py <command> --help` for individual options. The GUI follows
the same four steps: Create CA → Issue identity → Protect → Open. In the GUI,
"Show file fingerprint" does not automatically trust the root; enter the pin
you confirmed independently. All saved outputs refuse to overwrite existing
files, including decrypted documents. A package is limited to a 16 MiB
plaintext and a 24 MiB `.sdoc` file; both CLI and GUI use the same bounds.
The Appearance selector defaults to System: Qt keeps the desktop's native
controls, palette and font while the custom navigation follows its colors.
Light and Dark override the palette for the current session only. File
operations run off the UI thread; close waits for an active operation to
finish. Icons are bundled Lucide (ISC), Tabler and Heroicons (MIT) SVGs (see
`securedoc/gui/icons/LICENSE*`), never fetched at runtime. PySide6-Essentials
is LGPLv3-licensed; the project code remains MIT-licensed. The layout follows
[Qt's accessibility guidance](https://doc.qt.io/qt-6/accessible.html) on
keyboard navigation, labels, and contrast; native assistive-technology and
platform appearance still need testing.
See [desktop UI decisions and verification](docs/GUI.md) for design sources
and native testing limits.

**Protect your environment:** Use strong, unique key passwords, separate
storage/backups for the CA key, and secure file permissions. On POSIX, encrypted
keys and recovered plaintext are created mode `0600`. Windows permissions
depend on the account and filesystem ACLs. A wrong password, wrong identity,
untrusted pin, invalid signature, malformed package or failed AES-GCM tag
rejects the open operation before any decrypted output is written.

## Security design and limitations

The `.sdoc` JSON has a strict field set, version, bounded lengths and duplicate
key rejection. Sender certificate, recipient fingerprint, nonce, encrypted AES
key and filename are signed with RSA-PSS/SHA-256 along with the AES-GCM
ciphertext. Metadata is also AES-GCM additional authenticated data. The random
AES-256 key is wrapped to the recipient with RSA-OAEP/SHA-256. Opening checks
the caller-supplied root fingerprint and the root's self-signature, certificate
dates/usage, issuer signature and signing certificate, then checks the package
signature and decrypts. This is **local cryptographic validation**, not a
complete PKI trust service: certificates can be revoked without this version
knowing, and the CA's real-world vetting is out of scope. For the issuance
model see [docs/PKI.md](docs/PKI.md); for build limits see
[docs/CI.md](docs/CI.md) and [SECURITY.md](SECURITY.md).

There is no network API, so replay protection for authenticated *requests* is
not applicable here; opening the same stored document twice is allowed.
No forward secrecy, multi-recipient support, CA key rotation, OS trust-store
integration, keychain, online revocation, or legal identity guarantee exists.
File metadata may reveal who is communicating. An already-compromised device,
weak password, compromised CA or dishonest trusted pin defeats protections.

## Tests and development

```sh
python -m pytest -v
python -m pytest --cov=securedoc --cov-report=term-missing
python -m ruff check .
python -m black --check .
```

Tests generate temporary keys and files; no real private keys or fixtures are
tracked. Offscreen widget tests are skipped when Qt host libraries are absent.
A Linux development Dockerfile supports **headless CLI/core tests only**.
`docker build -t securedoc-nepal:dev .` then
`docker run --rm --network none securedoc-nepal:dev python -m pytest -v`
runs those tests; the default container command prints CLI help, not a GUI.
GitHub CI defines a native OS/Python matrix. Native packaging is defined in
`.github/workflows/native-build.yml` (Python 3.13), using `scripts/build.py`;
it builds a GUI and a separate console CLI. Tag builds create **unpublished
draft prereleases**, never an automatic public release. See
[docs/CI.md](docs/CI.md) for evidence requirements and platform limitations.
Do not claim Windows/macOS execution merely because workflows exist.

## Project structure

`securedoc/crypto/` implements certificates and package cryptography;
`security/` validates an explicitly pinned direct-issuer chain; `services/`
owns file workflows, shared by `cli.py` and `gui/desktop.py`. `tests/` contains
positive and adversarial tests. `app.py` starts the GUI or CLI, `cli_entry.py`
is the native console bundle entry point, and `scripts/build.py` prepares
isolated native archives. No mutable data is saved next to an executable.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). This
project uses the [MIT License](LICENSE). Do not upload keys or documents to
issues, CI artifacts or releases.

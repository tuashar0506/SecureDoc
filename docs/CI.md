# CI, native packaging, and draft releases

`.github/workflows/ci.yml` tests the shared CLI/crypto core on Ubuntu,
Windows and macOS with Python 3.11, 3.13 and 3.14. It also checks Ruff and
Black. The tests generate random temporary identities; no runtime documents,
passwords, keys or certificates are uploaded.

`.github/workflows/native-build.yml` runs on pushes to `main`, pull requests,
manual dispatch and `v*` tags.
It installs Python 3.13, verifies PySide6 Qt can be imported, runs the full test suite
and checks style on **each** native runner. `scripts/build.py` runs PyInstaller
locally on each runner: a GUI bundle plus a separate console CLI bundle; it
smoke-tests the **bundled CLI** using `--help` and briefly launches the **bundled
GUI** (`gui --smoke`; under Xvfb on headless Linux). The archives contain the bundles
and public project documentation, not runtime user data or test files.
Artifact names include package version, runner OS and detected CPU
architecture. Build artifacts expire after 7 days.
The Linux runner installs Qt XCB dependencies and checks `libqxcb.so` with
`ldd` before packaging. A previous Xvfb smoke launch aborted because XCB
libraries were missing; this dependency fix still needs a successful Actions
rerun before the Linux CI build can be claimed as passed.

Only a `v*` tag exactly matching `pyproject.toml` can create an **unpublished
draft prerelease**, after all three builds and tests pass. Publication requires
a human to inspect the artifacts and publish the draft. Workflow dispatch
and branch/PR runs build artifacts but do not create a release. These packages are **not**
signed or notarized. The repository does not claim a build has passed until its
GitHub Actions logs and artifacts have actually been inspected.

## Native verification still required

Launching the GUI briefly does **not** prove that dialogs work, or that the
cryptographic workflow operates inside a frozen GUI. Before publishing, unpack
each archive on the intended native OS,
run the GUI and console app, check certificate issuance and a test-only
protect/open round trip, verify no runtime key/certificate/plaintext exists in
the archive, and inspect OS-specific permissions and antivirus/quarantine
behavior. On macOS, quarantine and unsigned-app warnings are expected until
codesigning and notarization are arranged. On Linux, ensure the target system
has the required Qt/display libraries. No installer, application icon, or
automatic updater is included. Do not publish as a finished security product;
the offline tool has no revocation enforcement or real-world identity vetting.

Local checks inside the project environment:

```sh
python -m pytest -v
python -m ruff check .
python -m black --check .
python -m pip install -e '.[dev,build]'
python scripts/build.py
```

The last two commands require PyInstaller and a working Qt installation and
display (Xvfb is used for the Linux smoke test). Install project Python
dependencies only in `.venv`; Linux Qt display libraries may require system
packages. A local Linux bundle and offscreen GUI smoke launch succeeded using
temporary extracted libraries outside the repository. That does not verify an
ordinary host installation, native X11/Wayland display, or Windows/macOS builds.

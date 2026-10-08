# Continuous integration and release boundaries

The repository configures a **test-only** GitHub Actions workflow at
`.github/workflows/ci.yml`. It runs on pushes to `main`, pull requests and
manual dispatch. Its test matrix installs `requirements.txt` and runs the
pytest suite on native Ubuntu, Windows and macOS runners with Python 3.11,
3.13 and 3.14. A separate Ubuntu/Python 3.13 job runs Ruff and Black. Jobs have
read-only repository permissions, do not retain checkout credentials, and
upload no artifacts or test-generated private keys. Pull requests do not need
repository secrets.

**A workflow file is not evidence of a successful run.** After pushing, check
the repository's Actions tab and inspect all matrix jobs and their logs. A
green Linux test does not imply that Windows or macOS passed. To reproduce
locally with the active project virtual environment:

```sh
python -m pip install -r requirements.txt
python -m pytest -v
python -m ruff check .
python -m black --check .
```

## What is intentionally not automated yet

There is no desktop GUI, validated document workflow, PyInstaller spec,
native package or release workflow. The current `app.py` reports development
status only. Publishing it as a finished desktop security product, or tagging
it `v1.0.0`, would misrepresent the code. Do not upload private keys,
certificates, audit logs or document files as build or test artifacts.

Before adding a release workflow: implement and test the core document
workflows and GUI, select an application-data directory outside the bundled
executable, and test a reproducible PyInstaller configuration on each native
runner. Check each package by launching the actual application and exercising
non-sensitive workflows. Explicitly exclude runtime data and secrets from
the build context and archives. Make publishing depend on passing CI and
verified build jobs; require an explicit reviewed tag/release decision. No
published platform or security claim should precede evidence from that
platform and workflow.

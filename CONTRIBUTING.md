# Contributing to SecureDoc Nepal

This is educational software under construction. Please keep contributions
small, reviewable, tested and honest about their security properties.

## Local setup

Follow the platform-specific instructions in [README.md](README.md). Activate
the project `.venv` before installing dependencies or running checks.
For an optional isolated CLI test environment, see the Docker instructions
there; never mount local secrets or the Docker socket into a container.

## Before proposing a change

1. Explain the security goal and threat being addressed; use established
   `cryptography` APIs rather than designing new cryptographic algorithms.
2. Add meaningful positive and negative tests, especially for malformed input,
   authentication failures, trust decisions and wrong keys.
3. Run `python -m pytest`, `python -m ruff check .` and
   `python -m black --check .` in the virtual environment.
4. Check `git status`, `git diff`, then stage only intended files and review
   `git diff --staged` before committing.
5. Never include private keys, real certificates, passwords, secrets or
   sensitive document samples. Clearly mark any synthetic test fixture.

Please report security concerns privately as described in [SECURITY.md](SECURITY.md).
Do not claim a passing test or a working platform that has not been checked.

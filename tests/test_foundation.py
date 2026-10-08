"""Ensure the foundation entry point does not pretend to protect documents."""

from pytest import CaptureFixture

import securedoc
from app import main


def test_placeholder_reports_unimplemented_security(
    capsys: CaptureFixture[str],
) -> None:
    """Users must not mistake the placeholder for an operational security tool."""
    main()
    output = capsys.readouterr().out
    assert "document workflows are not implemented yet" in output


def test_package_import_exposes_foundation_version() -> None:
    """The installed package should be importable from the development venv."""
    assert securedoc.__version__ == "0.0.1"

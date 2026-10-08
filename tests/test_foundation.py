"""Ensure the entry point exposes a headless command line."""

import sys
from types import ModuleType

import pytest
from pytest import CaptureFixture

import securedoc
from securedoc.cli import main


def test_help_lists_document_workflows(
    capsys: CaptureFixture[str],
) -> None:
    """Help can run without importing the optional native desktop toolkit."""
    with pytest.raises(SystemExit) as exit_status:
        main(["--help"])
    assert exit_status.value.code == 0
    output = capsys.readouterr().out
    assert "seal" in output and "open" in output


def test_package_import_exposes_foundation_version() -> None:
    """The installed package should be importable from the development venv."""
    assert securedoc.__version__ == "0.0.1"


def test_gui_smoke_is_dispatched_without_running_a_display(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []
    fake = ModuleType("securedoc.gui.desktop")
    fake.launch = lambda *, smoke: calls.append(smoke)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "securedoc.gui.desktop", fake)
    assert main(["gui", "--smoke"]) == 0
    assert calls == [True]

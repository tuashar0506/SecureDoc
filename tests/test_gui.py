"""Offscreen widget and workflow wiring checks; not a native GUI sign-off."""

import json
import os
import secrets

import pytest


@pytest.fixture(scope="module")
def app():
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        pytest.skip(f"Qt host libraries unavailable: {exc}")

    application = QApplication.instance() or QApplication([])
    yield application


def test_pages_theme_and_trust_are_explicit(app) -> None:
    from PySide6.QtGui import QPalette
    from PySide6.QtWidgets import QLineEdit

    from securedoc.gui.desktop import COLORS, Desktop, icon

    original = QPalette(app.palette())
    window = Desktop()
    assert len(window.nav) == 4
    assert len(window.actions) == 4
    assert not window.trust.isVisible()
    window.show()
    window.select_page(2)
    assert window.trust.isVisible()
    assert (
        "independent channel"
        in window.trust.findChildren(type(window.subtitle))[-1].text()
    )
    assert window.root_pin.text() == ""
    assert window.inputs["seal_password"].echoMode() == QLineEdit.EchoMode.Password
    app.processEvents()
    assert window.stack.height() == window.stack.currentWidget().sizeHint().height()
    assert window.theme.currentText() == "System"
    assert app.palette() == original
    assert "QWidget {" not in window.styleSheet()
    assert not icon("tabler-folder-open", "#000000").isNull()
    assert not icon("heroicons-shield-check", "#000000").isNull()
    assert all(not button.icon().isNull() for button in window.browse)
    window.theme.setCurrentText("Dark")
    assert COLORS["Dark"]["accent"] in window.styleSheet()
    assert (
        app.palette().color(QPalette.ColorRole.Base).name()
        == COLORS["Dark"]["surface"].lower()
    )
    window.theme.setCurrentText("Light")
    assert COLORS["Light"]["accent"] in window.styleSheet()
    window.theme.setCurrentText("System")
    assert app.palette() == original
    window.select_page(1)
    app.processEvents()
    assert window.stack.sizeHint().height() > window.stack.widget(0).sizeHint().height()
    window.close()


def test_system_palette_updates_custom_chrome(app) -> None:
    from PySide6.QtGui import QColor, QPalette

    from securedoc.gui.desktop import Desktop

    original = QPalette(app.palette())
    window = Desktop()
    try:
        new = QPalette(original)
        new.setColor(QPalette.ColorRole.Highlight, QColor("#784599"))
        app.setPalette(new)
        assert "#784599" in window.styleSheet()
        assert app.palette().color(QPalette.ColorRole.Highlight) == QColor("#784599")
    finally:
        window.close()
        app.setPalette(original)


def test_wayland_preference_respects_user_platform(monkeypatch) -> None:
    from securedoc.gui import desktop

    monkeypatch.setattr(desktop.sys, "platform", "linux")
    monkeypatch.setenv("XDG_SESSION_TYPE", "wayland")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("QT_QPA_PLATFORM", raising=False)
    desktop.prefer_wayland()
    assert os.environ["QT_QPA_PLATFORM"] == "wayland;xcb"
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    desktop.prefer_wayland()
    assert os.environ["QT_QPA_PLATFORM"] == "offscreen"
    monkeypatch.delenv("QT_QPA_PLATFORM")
    monkeypatch.setenv("XDG_SESSION_TYPE", "x11")
    desktop.prefer_wayland()
    assert "QT_QPA_PLATFORM" not in os.environ


def test_missing_trust_or_fields_never_start_worker(app) -> None:
    from securedoc.gui.desktop import Desktop

    window = Desktop()
    window.select_page(3)
    window.inputs["open_password"].setText("test-only-password")
    window.start(3)
    assert window._thread is None
    assert window.inputs["open_password"].text() == ""
    assert "Complete:" in window.status.text()
    assert "Trusted root" in window.status.text()
    window.close()


def test_submitted_password_is_cleared_and_result_returned(app, monkeypatch, tmp_path):
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QMessageBox

    from securedoc.gui import desktop

    seen = []
    monkeypatch.setattr(
        desktop,
        "initialize_ca",
        lambda key, cert, password: seen.append((key, cert, password)) or "A" * 64,
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    window = desktop.Desktop()
    window.inputs["ca_key"].setText(str(tmp_path / "root.key"))
    window.inputs["ca_cert"].setText(str(tmp_path / "root.pem"))
    window.inputs["ca_password"].setText("example-password")
    window.start(0)
    assert window.inputs["ca_password"].text() == ""
    loop = QEventLoop()
    window._thread.finished.connect(loop.quit)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    app.processEvents()
    assert window._thread is None
    assert seen == [(tmp_path / "root.key", tmp_path / "root.pem", "example-password")]
    assert "independently" in window.status.text()
    window.close()


def test_worker_keeps_issuance_separate_from_trust(app, monkeypatch, tmp_path) -> None:
    from securedoc.gui import desktop

    seen = []

    def issue(*args, **kwargs):
        seen.append((args, kwargs))

    monkeypatch.setattr(desktop, "issue_identity", issue)
    values = {
        "issue_root_key": str(tmp_path / "root.key"),
        "issue_root_password": "test-password",
        "issue_key": str(tmp_path / "user.key"),
        "issue_cert": str(tmp_path / "user.pem"),
        "issue_password": "new-password",
        "issue_name": "Test",
        "issue_org": "Demo",
    }
    worker = desktop.Worker(1, values, str(tmp_path / "root.pem"), "A" * 64)
    messages = []
    worker.completed.connect(lambda ok, message: messages.append((ok, message)))
    worker.run()
    assert seen[0][0][2] == "A" * 64
    assert messages[0][0] is True
    assert "not been independently verified" in messages[0][1]
    assert values == {}


def test_worker_reports_rejection_without_success(app, monkeypatch, tmp_path) -> None:
    from securedoc.gui import desktop
    from securedoc.utils.exceptions import DocumentError

    def reject(*args):
        raise DocumentError("Authentication failed.")

    monkeypatch.setattr(desktop, "recover_file", reject)
    values = {
        "open_in": str(tmp_path / "in.sdoc"),
        "open_out": str(tmp_path / "out.txt"),
        "open_key": str(tmp_path / "user.key"),
        "open_cert": str(tmp_path / "user.pem"),
        "open_password": "wrong-password",
    }
    worker = desktop.Worker(3, values, str(tmp_path / "root.pem"), "A" * 64)
    messages = []
    worker.completed.connect(lambda ok, message: messages.append((ok, message)))
    worker.run()
    assert messages == [(False, "Authentication failed.")]
    assert values == {}


def test_real_gui_workflows_and_rejected_open(app, tmp_path) -> None:
    """Exercise each GUI action against generated temporary identities."""
    from securedoc.gui.desktop import Worker

    def perform(action, values, root="", pin=""):
        result = []
        worker = Worker(action, values, root, pin)
        worker.completed.connect(lambda ok, message: result.append((ok, message)))
        worker.run()
        assert values == {}
        assert len(result) == 1
        return result[0]

    root_key, root_cert = tmp_path / "root.key", tmp_path / "root.pem"
    ca_password, sender_password, recipient_password = (
        secrets.token_urlsafe(32) for _ in range(3)
    )
    ok, message = perform(
        0,
        {
            "ca_key": str(root_key),
            "ca_cert": str(root_cert),
            "ca_password": ca_password,
        },
    )
    assert ok
    pin = message.rsplit(" ", 1)[-1]
    assert len(pin) == 64
    for name, password in (
        ("sender", sender_password),
        ("recipient", recipient_password),
    ):
        ok, message = perform(
            1,
            {
                "issue_root_key": str(root_key),
                "issue_root_password": ca_password,
                "issue_key": str(tmp_path / f"{name}.key"),
                "issue_cert": str(tmp_path / f"{name}.pem"),
                "issue_password": password,
                "issue_name": name,
                "issue_org": "Test",
            },
            str(root_cert),
            pin,
        )
        assert ok, message
    source = tmp_path / "example.txt"
    source.write_bytes(b"Test-only document")
    package = tmp_path / "example.sdoc"
    ok, message = perform(
        2,
        {
            "seal_in": str(source),
            "seal_out": str(package),
            "seal_key": str(tmp_path / "sender.key"),
            "seal_cert": str(tmp_path / "sender.pem"),
            "seal_recipient": str(tmp_path / "recipient.pem"),
            "seal_password": sender_password,
        },
        str(root_cert),
        pin,
    )
    assert ok, message
    assert b"Test-only document" not in package.read_bytes()
    output = tmp_path / "recovered.txt"
    correct = {
        "open_in": str(package),
        "open_out": str(output),
        "open_key": str(tmp_path / "recipient.key"),
        "open_cert": str(tmp_path / "recipient.pem"),
        "open_password": recipient_password,
    }
    for changes, trusted_pin in (
        ({"open_password": "wrong-password"}, pin),
        (
            {
                "open_key": str(tmp_path / "sender.key"),
                "open_password": sender_password,
            },
            pin,
        ),
        ({}, "0" * 64 if pin != "0" * 64 else "F" * 64),
    ):
        values = correct | changes
        ok, message = perform(3, values, str(root_cert), trusted_pin)
        assert not ok, message
        assert not output.exists()
    damaged = tmp_path / "damaged.sdoc"
    data = json.loads(package.read_bytes())
    data["ciphertext"] = "AAAA"
    damaged.write_text(json.dumps(data), encoding="utf-8")
    ok, message = perform(3, correct | {"open_in": str(damaged)}, str(root_cert), pin)
    assert not ok, message
    assert not output.exists()
    ok, message = perform(3, correct.copy(), str(root_cert), pin)
    assert ok, message
    assert output.read_bytes() == source.read_bytes()

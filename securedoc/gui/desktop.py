"""Qt desktop workspace; all security decisions live in shared workflows."""

import os
import sys
from importlib.resources import files
from pathlib import Path
from string import Template

from PySide6.QtCore import QByteArray, QObject, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from securedoc.services.workflows import (
    initialize_ca,
    issue_identity,
    protect_file,
    recover_file,
    root_fingerprint,
)
from securedoc.utils.exceptions import SecureDocError

PAGES = (
    ("Create root", "shield-check", "Create root"),
    ("Issue identity", "key-round", "Issue certificate"),
    ("Protect file", "file-lock", "Protect document"),
    ("Open file", "lock-keyhole", "Verify & decrypt"),
)

FIELDS = (
    (
        ("New root key", "ca_key", "save"),
        ("New root certificate", "ca_cert", "save"),
        ("New key password", "ca_password", "password"),
    ),
    (
        ("Root private key", "issue_root_key", "open"),
        ("CA key password", "issue_root_password", "password"),
        ("Common name", "issue_name", "text"),
        ("Organization", "issue_org", "text"),
        ("New user key", "issue_key", "save"),
        ("New user certificate", "issue_cert", "save"),
        ("New user password", "issue_password", "password"),
    ),
    (
        ("Document", "seal_in", "open"),
        ("New .sdoc output", "seal_out", "save"),
        ("Signer private key", "seal_key", "open"),
        ("Signer certificate", "seal_cert", "open"),
        ("Recipient certificate", "seal_recipient", "open"),
        ("Signer password", "seal_password", "password"),
    ),
    (
        (".sdoc package", "open_in", "open"),
        ("New output document", "open_out", "save"),
        ("Recipient private key", "open_key", "open"),
        ("Recipient certificate", "open_cert", "open"),
        ("Recipient password", "open_password", "password"),
    ),
)

DESCRIPTIONS = (
    "Keep the encrypted CA key private. Share only the public certificate; "
    "confirm its fingerprint separately.",
    "Names are supplied by the CA operator. Issuing a certificate does not "
    "verify a real person's identity.",
    "Choose the signer's key and the recipient's public certificate. "
    "Maximum document size: 16 MiB.",
    "Choose a new output path. No plaintext is saved unless all checks pass.",
)

COLORS = {
    "Light": {
        "bg": "#F6F7F9",
        "surface": "#FFFFFF",
        "text": "#1C2732",
        "muted": "#495B69",
        "border": "#D2DBE1",
        "accent": "#075B76",
        "soft": "#EAF0F3",
        "sidebar": "#F0F3F5",
        "on_accent": "#FFFFFF",
    },
    "Dark": {
        "bg": "#161C22",
        "surface": "#212A32",
        "text": "#F1F5F7",
        "muted": "#B9C8D2",
        "border": "#45535E",
        "accent": "#83D7E4",
        "soft": "#303D46",
        "sidebar": "#1C252D",
        "on_accent": "#11262D",
    },
}


def icon(name: str, color: str, size: int = 24) -> QIcon:
    """Tint a bundled, fixed SVG; never load document-supplied SVG content."""
    svg = files("securedoc.gui").joinpath("icons", f"{name}.svg").read_text()
    renderer = QSvgRenderer(QByteArray(svg.replace("currentColor", color).encode()))
    ratio = QApplication.instance().devicePixelRatio()
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


def prefer_wayland() -> None:
    """Use native Wayland on Wayland sessions; leave explicit Qt choices alone."""
    if (
        sys.platform == "linux"
        and not os.environ.get("QT_QPA_PLATFORM")
        and os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland"
        and os.environ.get("WAYLAND_DISPLAY")
    ):
        os.environ["QT_QPA_PLATFORM"] = "wayland;xcb"


def system_colors(palette: QPalette) -> dict[str, str]:
    """Draw only the custom chrome with colors from the desktop palette."""
    role = QPalette.ColorRole
    return {
        "bg": palette.color(role.Window).name(),
        "surface": palette.color(role.Base).name(),
        "text": palette.color(role.WindowText).name(),
        "muted": palette.color(role.Text).name(),
        "border": palette.color(role.Mid).name(),
        "accent": palette.color(role.Highlight).name(),
        "soft": palette.color(role.AlternateBase).name(),
        "sidebar": palette.color(role.Window).name(),
        "on_accent": palette.color(role.HighlightedText).name(),
    }


def theme_palette(colors: dict[str, str]) -> QPalette:
    """Cover all standard widget roles, including selections and disabled text."""
    palette = QPalette()
    role = QPalette.ColorRole
    for key, roles in {
        "bg": (role.Window, role.Button),
        "surface": (role.Base,),
        "soft": (role.AlternateBase,),
        "text": (role.WindowText, role.Text, role.ButtonText),
        "accent": (role.Highlight, role.Link),
        "on_accent": (role.HighlightedText,),
        "border": (role.Mid, role.Dark),
        "muted": (role.PlaceholderText,),
    }.items():
        for item in roles:
            palette.setColor(item, QColor(colors[key]))
    for item in (role.WindowText, role.Text, role.ButtonText):
        palette.setColor(QPalette.ColorGroup.Disabled, item, QColor(colors["muted"]))
    return palette


class Worker(QObject):
    completed = Signal(bool, str)

    def __init__(self, action: int, values: dict[str, str], root: str, pin: str):
        super().__init__()
        self.action, self.values, self.root, self.pin = action, values, root, pin

    def run(self) -> None:
        v, root, pin = self.values, Path(self.root), self.pin
        try:
            if self.action == 0:
                fingerprint = initialize_ca(
                    Path(v["ca_key"]), Path(v["ca_cert"]), v["ca_password"]
                )
                message = (
                    "Root created. Confirm and record this fingerprint "
                    f"independently: {fingerprint}"
                )
            elif self.action == 1:
                issue_identity(
                    Path(v["issue_root_key"]),
                    root,
                    pin,
                    v["issue_root_password"],
                    Path(v["issue_key"]),
                    Path(v["issue_cert"]),
                    v["issue_password"],
                    name=v["issue_name"],
                    organization=v["issue_org"],
                )
                message = (
                    "User key and certificate created. Identity has not been "
                    "independently verified."
                )
            elif self.action == 2:
                protect_file(
                    Path(v["seal_in"]),
                    Path(v["seal_out"]),
                    Path(v["seal_key"]),
                    Path(v["seal_cert"]),
                    Path(v["seal_recipient"]),
                    root,
                    pin,
                    v["seal_password"],
                )
                message = "Signed and encrypted package saved."
            else:
                name = recover_file(
                    Path(v["open_in"]),
                    Path(v["open_out"]),
                    Path(v["open_key"]),
                    Path(v["open_cert"]),
                    root,
                    pin,
                    v["open_password"],
                )
                message = (
                    f"Verified, decrypted and saved. Package document name: {name}"
                )
            self.completed.emit(True, message)
        except (SecureDocError, OSError) as exc:
            self.completed.emit(False, str(exc))
        finally:
            # Drop password references as soon as the operation ends.
            self.values.clear()


class PageStack(QStackedWidget):
    """Use the current form's height, not the tallest hidden form's height."""

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return self.currentWidget().sizeHint()

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return self.currentWidget().minimumSizeHint()


class Desktop(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SecureDoc Nepal · Document workspace")
        self.resize(1080, 780)
        self.setMinimumSize(760, 580)
        self.inputs: dict[str, QLineEdit] = {}
        self.nav: list[QPushButton] = []
        self.browse: list[QPushButton] = []
        self.actions: list[QPushButton] = []
        self._override_palette = False
        self._thread: QThread | None = None
        self._worker: Worker | None = None
        self._build()
        self.theme.setCurrentText("System")
        self.theme.currentTextChanged.connect(self.apply_theme)
        QApplication.instance().styleHints().colorSchemeChanged.connect(
            self._system_theme_changed
        )
        QApplication.instance().paletteChanged.connect(self._system_palette_changed)
        self.apply_theme()

    def _build(self) -> None:
        shell = QHBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(216)
        sidebar = QVBoxLayout(side)
        sidebar.setContentsMargins(16, 28, 16, 20)
        sidebar.setSpacing(6)
        brand = QLabel("SecureDoc Nepal")
        brand.setObjectName("brand")
        sidebar.addWidget(brand)
        caption = QLabel("Document workspace")
        caption.setObjectName("eyebrow")
        sidebar.addWidget(caption)
        sidebar.addSpacing(28)
        for index, (name, _, _) in enumerate(PAGES):
            button = QPushButton(name)
            button.setObjectName("nav")
            button.setProperty("selected", index == 0)
            button.setMinimumHeight(46)
            button.setIconSize(QSize(20, 20))
            button.clicked.connect(lambda _=False, page=index: self.select_page(page))
            sidebar.addWidget(button)
            self.nav.append(button)
        sidebar.addStretch()
        caution = QLabel("Educational software\nNot audited for real secrets")
        caution.setObjectName("sidebarNote")
        caution.setWordWrap(True)
        sidebar.addWidget(caution)
        shell.addWidget(side)

        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(28, 24, 28, 20)
        column.setSpacing(18)
        top = QHBoxLayout()
        title = QLabel("Your files stay on this device")
        title.setObjectName("topTitle")
        top.addWidget(title)
        top.addStretch()
        top.addWidget(QLabel("Appearance"))
        self.theme = QComboBox()
        self.theme.addItems(["System", "Light", "Dark"])
        self.theme.setAccessibleName("Appearance theme")
        self.theme.setMinimumWidth(108)
        top.addWidget(self.theme)
        column.addLayout(top)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 4, 12)
        body_layout.setSpacing(18)
        self.step = QLabel()
        self.step.setObjectName("eyebrow")
        body_layout.addWidget(self.step)
        self.heading = QLabel()
        self.heading.setObjectName("heading")
        body_layout.addWidget(self.heading)
        self.subtitle = QLabel()
        self.subtitle.setObjectName("subtitle")
        self.subtitle.setWordWrap(True)
        body_layout.addWidget(self.subtitle)

        self.trust = QFrame()
        self.trust.setObjectName("card")
        trust_layout = QVBoxLayout(self.trust)
        trust_layout.setContentsMargins(24, 20, 24, 20)
        trust_layout.setSpacing(12)
        trust_header = QHBoxLayout()
        self.trust_icon = QLabel()
        self.trust_icon.setFixedSize(24, 24)
        trust_header.addWidget(self.trust_icon)
        trust_title = QLabel("Trusted root · confirm out of band")
        trust_title.setObjectName("cardTitle")
        trust_header.addWidget(trust_title)
        trust_header.addStretch()
        trust_layout.addLayout(trust_header)
        self.root_cert = self._field(
            trust_layout, "Root certificate", "root_cert", "open"
        )
        self.root_pin = self._field(
            trust_layout, "Trusted SHA-256 fingerprint", "root_pin", "text"
        )
        self.root_pin.setPlaceholderText(
            "64 hexadecimal characters from a separate trusted channel"
        )
        fingerprint = QPushButton("Show file fingerprint (unverified)")
        fingerprint.setObjectName("secondary")
        fingerprint.clicked.connect(self.show_fingerprint)
        trust_layout.addWidget(fingerprint, alignment=Qt.AlignmentFlag.AlignLeft)
        hint = QLabel(
            "Viewing this file's fingerprint does not establish trust. Compare "
            "it through an independent channel before entering a pin."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        trust_layout.addWidget(hint)
        body_layout.addWidget(self.trust)

        self.stack = PageStack()
        self.stack.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
        )
        for index, fields in enumerate(FIELDS):
            card = QFrame()
            card.setObjectName("card")
            form = QVBoxLayout(card)
            form.setContentsMargins(24, 22, 24, 24)
            form.setSpacing(13)
            label = QLabel("Details")
            label.setObjectName("eyebrow")
            form.addWidget(label)
            for text, key, kind in fields:
                self._field(form, text, key, kind)
            form.addSpacing(8)
            button = QPushButton(PAGES[index][2])
            button.setObjectName("primary")
            button.setMinimumHeight(44)
            button.clicked.connect(lambda _=False, page=index: self.start(page))
            form.addWidget(button, alignment=Qt.AlignmentFlag.AlignRight)
            self.actions.append(button)
            self.stack.addWidget(card)
        body_layout.addWidget(self.stack)
        body_layout.addStretch()
        scroll.setWidget(body)
        column.addWidget(scroll, 1)
        self.status = QLabel("Ready · Outputs must use new, unused file paths.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(42)
        self.status.setAccessibleName("Operation status")
        column.addWidget(self.status)
        shell.addWidget(content, 1)
        self.select_page(0)

    def _field(self, layout: QVBoxLayout, label: str, key: str, kind: str) -> QLineEdit:
        title = QLabel(label)
        layout.addWidget(title)
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setAccessibleName(label)
        edit.setMinimumHeight(39)
        title.setBuddy(edit)
        if kind == "password":
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        row.addWidget(edit, 1)
        if kind in ("open", "save"):
            browse = QPushButton("Browse…")
            browse.setObjectName("secondary")
            browse.setAccessibleName(f"Browse for {label.lower()}")
            browse.setMinimumHeight(39)
            browse.setIconSize(QSize(18, 18))
            self.browse.append(browse)
            browse.clicked.connect(
                lambda: self.pick(edit, kind == "save", key == "seal_out")
            )
            row.addWidget(browse)
        layout.addLayout(row)
        self.inputs[key] = edit
        return edit

    def pick(self, edit: QLineEdit, save: bool, package: bool) -> None:
        dialog = QFileDialog(
            self, "Choose a new output" if save else "Choose a file", str(Path.home())
        )
        if save:
            dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
            dialog.setOption(QFileDialog.Option.DontConfirmOverwrite, True)
            if package:
                dialog.setNameFilter("SecureDoc package (*.sdoc)")
                dialog.setDefaultSuffix("sdoc")
        else:
            dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        if dialog.exec():
            edit.setText(dialog.selectedFiles()[0])

    def select_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self.stack.updateGeometry()
        self.trust.setVisible(index != 0)
        self.step.setText(f"Step {index + 1} of {len(PAGES)}")
        self.heading.setText(PAGES[index][0])
        self.subtitle.setText(DESCRIPTIONS[index])
        for number, button in enumerate(self.nav):
            button.setProperty("selected", index == number)
            button.style().unpolish(button)
            button.style().polish(button)
        self.apply_theme()

    def show_fingerprint(self) -> None:
        try:
            value = root_fingerprint(Path(self.root_cert.text().strip()))
        except (SecureDocError, OSError) as exc:
            QMessageBox.warning(self, "Cannot read certificate", str(exc))
        else:
            QMessageBox.information(
                self,
                "Unverified fingerprint",
                f"{value}\n\nCompare through an independent channel before "
                "entering it as trusted.",
            )

    def start(self, index: int) -> None:
        if self._thread is not None:
            return
        fields = FIELDS[index]
        values = {
            key: (
                self.inputs[key].text()
                if kind == "password"
                else self.inputs[key].text().strip()
            )
            for _, key, kind in fields
        }
        for _, key, kind in fields:
            if kind == "password":
                self.inputs[key].clear()
        missing = [label for label, key, _ in fields if not values[key]]
        if index != 0 and (
            not self.root_cert.text().strip() or not self.root_pin.text().strip()
        ):
            missing.append("Trusted root certificate and fingerprint")
        if missing:
            self.status.setText("Complete: " + ", ".join(missing))
            first = next(
                (self.inputs[key] for _, key, _ in fields if not values[key]),
                self.root_cert if not self.root_cert.text().strip() else self.root_pin,
            )
            values.clear()
            first.setFocus()
            return
        self.status.setText("Working… No existing output will be overwritten.")
        for button in self.actions:
            button.setEnabled(False)
        self._thread = QThread(self)
        self._worker = Worker(
            index, values, self.root_cert.text().strip(), self.root_pin.text().strip()
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.completed.connect(self.complete)
        self._worker.completed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self.thread_finished)
        self._thread.start()

    def complete(self, success: bool, message: str) -> None:
        self.status.setText(message)
        if success:
            QMessageBox.information(self, "Complete", message)
        else:
            QMessageBox.warning(self, "Operation stopped", message)

    def thread_finished(self) -> None:
        thread = self._thread
        # finished() can precede thread-local teardown; keep the QThread alive
        # until wait() confirms the native thread has actually exited.
        thread.wait()
        self._thread = None
        self._worker = None
        for button in self.actions:
            button.setEnabled(True)
        thread.deleteLater()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._thread is not None:
            self.status.setText(
                "Wait for the current operation to finish before closing."
            )
            event.ignore()
        else:
            if self._override_palette:
                self._override_palette = False
                QApplication.instance().setPalette(QPalette())
            event.accept()

    def _system_theme_changed(self, _scheme: Qt.ColorScheme) -> None:
        if self.theme.currentText() == "System":
            self.apply_theme()

    def _system_palette_changed(self, _palette: QPalette) -> None:
        if self.theme.currentText() == "System":
            self.apply_theme()

    def apply_theme(self, _choice: str = "") -> None:
        choice = self.theme.currentText()
        app = QApplication.instance()
        if choice == "System":
            if self._override_palette:
                # Relinquish overrides to the OS/platform theme.
                self._override_palette = False
                app.setPalette(QPalette())
            c = system_colors(app.palette())
        else:
            c = COLORS[choice]
            self._override_palette = True
            app.setPalette(theme_palette(c))
        css = files("securedoc.gui").joinpath("theme.qss").read_text()
        # Native inputs, buttons and dialogs remain native in System mode.
        self.setProperty("appearance", choice.lower())
        self.setStyleSheet(Template(css).substitute(**c))
        for button, (_, image, _) in zip(self.nav, PAGES, strict=True):
            button.setIcon(
                icon(
                    image,
                    c["on_accent"] if button.property("selected") else c["text"],
                    20,
                )
            )
        for button in self.browse:
            button.setIcon(icon("tabler-folder-open", c["text"], 18))
        self.trust_icon.setPixmap(
            icon("heroicons-shield-check", c["accent"]).pixmap(24)
        )


def launch(*, smoke: bool = False) -> None:
    if QApplication.instance() is None:
        prefer_wayland()
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("SecureDoc Nepal")
    window = Desktop()
    window.show()
    if smoke:
        QTimer.singleShot(500, app.quit)
    app.exec()

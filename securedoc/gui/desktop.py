"""Qt desktop workspace; all security decisions live in shared workflows."""

from importlib.resources import files
from pathlib import Path
from string import Template

from PySide6.QtCore import QByteArray, QObject, Qt, QThread, QTimer, Signal
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
        "bg": "#F5F7FB",
        "surface": "#FFFFFF",
        "text": "#152238",
        "muted": "#536378",
        "border": "#DCE3ED",
        "accent": "#145C72",
        "soft": "#E6F2F4",
        "sidebar": "#EDF3F7",
    },
    "Dark": {
        "bg": "#101824",
        "surface": "#1B2735",
        "text": "#EDF4F8",
        "muted": "#AFBECD",
        "border": "#37495A",
        "accent": "#76D1DC",
        "soft": "#263D4C",
        "sidebar": "#152130",
    },
}


def icon(name: str, color: str) -> QIcon:
    """Tint a bundled, fixed SVG; never load document-supplied SVG content."""
    svg = files("securedoc.gui").joinpath("icons", f"{name}.svg").read_text()
    renderer = QSvgRenderer(QByteArray(svg.replace("currentColor", color).encode()))
    pixmap = QPixmap(24, 24)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


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


class Desktop(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SecureDoc Nepal · Document workspace")
        self.resize(1080, 780)
        self.setMinimumSize(760, 580)
        self.inputs: dict[str, QLineEdit] = {}
        self.nav: list[QPushButton] = []
        self.actions: list[QPushButton] = []
        self._thread: QThread | None = None
        self._worker: Worker | None = None
        self._build()
        self.theme.setCurrentText("System")
        self.theme.currentTextChanged.connect(self.apply_theme)
        QApplication.instance().styleHints().colorSchemeChanged.connect(
            self._system_theme_changed
        )
        self.apply_theme()

    def _build(self) -> None:
        shell = QHBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(236)
        sidebar = QVBoxLayout(side)
        sidebar.setContentsMargins(18, 30, 18, 24)
        sidebar.setSpacing(8)
        brand = QLabel("SECUREDOC  /  NEPAL")
        brand.setObjectName("brand")
        sidebar.addWidget(brand)
        caption = QLabel("DOCUMENT WORKSPACE")
        caption.setObjectName("eyebrow")
        sidebar.addWidget(caption)
        sidebar.addSpacing(34)
        for index, (name, _, _) in enumerate(PAGES):
            button = QPushButton(f"{index + 1:02d}   {name}")
            button.setObjectName("nav")
            button.setProperty("selected", index == 0)
            button.setMinimumHeight(48)
            button.clicked.connect(lambda _=False, page=index: self.select_page(page))
            sidebar.addWidget(button)
            self.nav.append(button)
        sidebar.addStretch()
        caution = QLabel("EDUCATIONAL SOFTWARE\nNot audited for real secrets")
        caution.setObjectName("sidebarNote")
        caution.setWordWrap(True)
        sidebar.addWidget(caution)
        shell.addWidget(side)

        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(32, 26, 32, 24)
        column.setSpacing(16)
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
        trust_title = QLabel("Trusted root  ·  confirm out of band")
        trust_title.setObjectName("cardTitle")
        trust_layout.addWidget(trust_title)
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

        self.stack = QStackedWidget()
        for index, fields in enumerate(FIELDS):
            card = QFrame()
            card.setObjectName("card")
            form = QVBoxLayout(card)
            form.setContentsMargins(24, 22, 24, 24)
            form.setSpacing(13)
            label = QLabel("DETAILS")
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
        self.trust.setVisible(index != 0)
        self.step.setText(f"WORKFLOW  /  {index + 1:02d} OF 04")
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
            event.accept()

    def _system_theme_changed(self, _scheme: Qt.ColorScheme) -> None:
        if self.theme.currentText() == "System":
            self.apply_theme()

    def apply_theme(self, _choice: str = "") -> None:
        choice = self.theme.currentText()
        if choice == "System":
            choice = (
                "Dark"
                if QApplication.instance().styleHints().colorScheme()
                == Qt.ColorScheme.Dark
                else "Light"
            )
        c = COLORS[choice]
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(c["bg"]))
        palette.setColor(QPalette.ColorRole.Base, QColor(c["surface"]))
        palette.setColor(QPalette.ColorRole.Text, QColor(c["text"]))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(c["text"]))
        QApplication.instance().setPalette(palette)
        css = files("securedoc.gui").joinpath("theme.qss").read_text()
        self.setStyleSheet(
            Template(css).substitute(
                **c, primary_text=c["surface"] if choice == "Dark" else "#FFFFFF"
            )
        )
        for button, (_, image, _) in zip(self.nav, PAGES, strict=True):
            button.setIcon(
                icon(image, c["accent"] if button.property("selected") else c["muted"])
            )


def launch(*, smoke: bool = False) -> None:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("SecureDoc Nepal")
    app.setStyle("Fusion")
    window = Desktop()
    window.show()
    if smoke:
        QTimer.singleShot(500, app.quit)
    app.exec()

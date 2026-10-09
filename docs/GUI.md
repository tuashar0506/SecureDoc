# Desktop UI decisions and verification

The desktop interface uses Qt Widgets through PySide6-Essentials (LGPLv3), not
PyQt6 (GPLv3). This keeps the binding usable with this repository's MIT code.
The CLI and cryptographic services are unchanged; the UI never makes trust
decisions of its own.

The four visible steps match the file workflow: create a local root, issue a
certificate, protect a file, and verify/open it. Root certificate and trusted
pin are shared between the latter three steps; viewing a file's fingerprint
never fills the trusted pin. Saved file paths must be new and exclusive writes
are enforced by the shared workflow. Password inputs are masked and cleared on
submission. Status messages and dialog titles include text, not only color or
icons. Time-consuming work runs on a background Qt thread; the window cannot
close mid-operation. Appearance defaults to the OS color scheme, with explicit
light and dark selections for the current session; nothing is persisted.

The layout uses Qt's native controls, scrollable forms, label buddies and
visible keyboard focus. Navigation and actions include text alongside locally
bundled Lucide SVGs; no font, icon or network resource is requested at runtime.
The selected root is **not** a real-world identity proof. Fonts, contrast,
screen-reader semantics, dialogs, and scaling should be checked manually on
each native target OS before claiming accessibility or native GUI support.

Sources informing the design:

- [Qt accessibility: keyboard, color, scaling, assistive tools](https://doc.qt.io/qt-6/accessible.html)
- [Qt Widgets keyboard focus and tab navigation](https://doc.qt.io/qt-6/focus.html)
- [Qt for Python and open-source licensing](https://doc.qt.io/qtforpython/)
- [Lucide icons and ISC licensing](https://lucide.dev/)

Automated tests run Qt offscreen when host libraries are available, testing
theme selection, form/trust boundaries, password clearing, all four GUI worker
workflows and rejected wrong-password/wrong-identity/wrong-pin/tampered input.
A local Linux PyInstaller GUI bundle launched offscreen. Offscreen launches and
bundle smoke tests do **not** verify real desktop rendering or the complete
cryptographic workflow inside a frozen GUI.

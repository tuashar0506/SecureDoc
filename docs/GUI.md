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
close mid-operation. Appearance defaults to **System**, leaving Qt's platform
style, palette, font, controls and dialogs intact while coloring only custom
workspace chrome from the current system palette. Palette updates refresh the
chrome. Explicit Light and Dark modes set full Qt widget palettes and style the
window's controls for the current session; nothing is persisted. High-contrast
platform themes should be used with System mode rather than overridden.

On Linux, when `XDG_SESSION_TYPE=wayland` and `WAYLAND_DISPLAY` is present, the
launcher prefers Qt's native `wayland` plugin before `xcb`. An explicitly set
`QT_QPA_PLATFORM` always wins; X11 sessions and CI's Xvfb smoke test retain XCB.
Wayland requires a working compositor and Qt plugin; offscreen tests do not
verify native Wayland rendering, portals or fractional scaling.

The layout uses Qt's platform font, scrollable forms, label buddies and
visible keyboard focus. Navigation, browse and trust actions pair text with
locally bundled Lucide (ISC), Tabler (MIT) and Heroicons (MIT) SVGs, tinted to
the active palette. License texts are bundled in `securedoc/gui/icons/`. No
font, icon or network resource is requested at runtime.
The selected root is **not** a real-world identity proof. Fonts, contrast,
screen-reader semantics, dialogs, and scaling should be checked manually on
each native target OS before claiming accessibility or native GUI support.

Sources informing the design:

- [Qt accessibility: keyboard, color, scaling, assistive tools](https://doc.qt.io/qt-6/accessible.html)
- [Qt Widgets keyboard focus and tab navigation](https://doc.qt.io/qt-6/focus.html)
- [Qt for Python and open-source licensing](https://doc.qt.io/qtforpython/)
- [Qt platform plugin selection](https://doc.qt.io/qt-6/qpa.html#selecting-a-qpa-plugin)
- [Lucide icons and ISC licensing](https://lucide.dev/)
- [Tabler icons and MIT licensing](https://github.com/tabler/tabler-icons)
- [Heroicons and MIT licensing](https://github.com/tailwindlabs/heroicons)

Automated tests run Qt offscreen when host libraries are available, testing
theme selection, form/trust boundaries, password clearing, all four GUI worker
workflows and rejected wrong-password/wrong-identity/wrong-pin/tampered input.
A local Linux PyInstaller GUI bundle launched offscreen. Offscreen launches and
bundle smoke tests do **not** verify real desktop rendering or the complete
cryptographic workflow inside a frozen GUI.

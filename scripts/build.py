"""Build isolated, platform-native CLI and GUI bundles (no runtime user data).

Run only on the target operating system: python -m pip install -e '.[dev,build]'
then python scripts/build.py. Output goes to the ignored dist/ directory.
"""

import os
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
    "project"
]["version"]


def main() -> None:
    tag = os.environ.get("RELEASE_TAG", "")
    if tag and tag != f"v{VERSION}":
        raise SystemExit("Tag must match pyproject.toml version.")
    try:
        import tkinter  # noqa: F401 - PyInstaller needs a working native Tk
    except ImportError as exc:
        raise SystemExit("Native Tk support is required to build the GUI.") from exc

    for name, entry, windowed in (
        ("SecureDoc-Nepal", "app.py", True),
        ("SecureDoc-CLI", "cli_entry.py", False),
    ):
        args = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--name",
            name,
            "--distpath",
            str(DIST / "bundle"),
            "--workpath",
            str(ROOT / "build" / name),
            "--specpath",
            str(ROOT / "build"),
        ]
        if windowed:
            args.append("--windowed")
        subprocess.run([*args, entry], cwd=ROOT, check=True)

    exe = ".exe" if os.name == "nt" else ""
    cli = DIST / "bundle" / "SecureDoc-CLI" / f"SecureDoc-CLI{exe}"
    subprocess.run([str(cli), "--help"], cwd=ROOT, check=True, timeout=30)
    gui = DIST / "bundle" / "SecureDoc-Nepal" / f"SecureDoc-Nepal{exe}"
    if sys.platform == "darwin":
        gui = (
            DIST
            / "bundle"
            / "SecureDoc-Nepal.app"
            / "Contents"
            / "MacOS"
            / "SecureDoc-Nepal"
        )
    command = [str(gui), "gui", "--smoke"]
    if sys.platform == "linux" and not os.environ.get("DISPLAY"):
        command = ["xvfb-run", "-a", *command]
    subprocess.run(command, cwd=ROOT, check=True, timeout=45)
    for document in ("README.md", "SECURITY.md", "LICENSE"):
        shutil.copy2(ROOT / document, DIST / "bundle" / document)
    forbidden = {".env", "audit_logs", "private_keys", "revocation", "data"}
    for path in (DIST / "bundle").rglob("*"):
        if path.name in forbidden or path.suffix.lower() in {
            ".key",
            ".sdoc",
            ".p12",
            ".pfx",
        }:
            raise SystemExit(f"Forbidden runtime data in bundle: {path.name}")

    system = {"win32": "windows", "darwin": "macos", "linux": "linux"}.get(sys.platform)
    if system is None:
        raise SystemExit("Unsupported packaging platform.")
    architecture = (
        platform.machine()
        .lower()
        .replace("amd64", "x86_64")
        .replace("aarch64", "arm64")
    )
    archive = DIST / f"SecureDoc-Nepal-{VERSION}-{system}-{architecture}.zip"
    if sys.platform == "darwin":
        # ditto preserves macOS .app resources and framework symlinks.
        subprocess.run(
            [
                "ditto",
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                "bundle",
                str(archive),
            ],
            cwd=DIST,
            check=True,
        )
    else:
        shutil.make_archive(str(archive.with_suffix("")), "zip", DIST, "bundle")
    print(f"Created native build archive: {archive.name}")


if __name__ == "__main__":
    main()

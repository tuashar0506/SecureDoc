"""Release tags must match the project version before packaging begins."""

import os
import subprocess
import sys
from pathlib import Path


def test_build_rejects_mismatched_release_tag() -> None:
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "build.py")],
        cwd=root,
        env={**os.environ, "RELEASE_TAG": "v999.0.0"},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert "Tag must match" in result.stderr

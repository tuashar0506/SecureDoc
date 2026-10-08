"""Run the native GUI by default; pass a subcommand for headless CLI use."""

import sys

from securedoc.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["gui"]))

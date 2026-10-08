"""Argument-based CLI; passwords are prompted, never accepted on argv."""

import argparse
import getpass
import sys
from pathlib import Path

from securedoc.services.workflows import (
    initialize_ca,
    issue_identity,
    protect_file,
    recover_file,
    root_fingerprint,
)
from securedoc.utils.exceptions import SecureDocError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securedoc",
        description=(
            "SecureDoc Nepal coursework: explicitly pinned local X.509 workflows."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-ca", help="Create a local root CA")
    init.add_argument("--key", type=Path, required=True, help="New encrypted root key")
    init.add_argument("--cert", type=Path, required=True, help="New public root PEM")

    fingerprint = commands.add_parser(
        "fingerprint", help="Show a certificate SHA-256 pin"
    )
    fingerprint.add_argument("cert", type=Path)

    issue = commands.add_parser("issue", help="Issue an end-entity certificate")
    issue.add_argument("--root-key", type=Path, required=True)
    issue.add_argument("--root-cert", type=Path, required=True)
    issue.add_argument(
        "--root-pin", required=True, help="Trusted root SHA-256 fingerprint"
    )
    issue.add_argument("--name", required=True, help="Certificate common name")
    issue.add_argument("--organization", required=True)
    issue.add_argument("--key", type=Path, required=True, help="New encrypted user key")
    issue.add_argument("--cert", type=Path, required=True, help="New public user PEM")

    seal = commands.add_parser("seal", help="Encrypt and sign one file to .sdoc")
    seal.add_argument("source", type=Path)
    seal.add_argument("destination", type=Path)
    seal.add_argument("--signer-key", type=Path, required=True)
    seal.add_argument("--signer-cert", type=Path, required=True)
    seal.add_argument("--recipient-cert", type=Path, required=True)
    seal.add_argument("--root-cert", type=Path, required=True)
    seal.add_argument("--root-pin", required=True)

    recover = commands.add_parser("open", help="Verify and decrypt one .sdoc")
    recover.add_argument("source", type=Path)
    recover.add_argument("destination", type=Path)
    recover.add_argument("--recipient-key", type=Path, required=True)
    recover.add_argument("--recipient-cert", type=Path, required=True)
    recover.add_argument("--root-cert", type=Path, required=True)
    recover.add_argument("--root-pin", required=True)
    gui = commands.add_parser("gui", help="Open the graphical interface")
    gui.add_argument("--smoke", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Return 0 for success, 1 for rejected inputs; argparse handles usage."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "gui":
            from securedoc.gui.desktop import launch

            launch(smoke=args.smoke)
        elif args.command == "fingerprint":
            print(root_fingerprint(args.cert))
            print("Parsing is NOT trust. Confirm this pin via an independent channel.")
        elif args.command == "init-ca":
            password = getpass.getpass("New CA key password (12+ characters): ")
            print("Root fingerprint:", initialize_ca(args.key, args.cert, password))
            print("Record and verify this fingerprint via an independent channel.")
        elif args.command == "issue":
            root_password = getpass.getpass("CA key password: ")
            password = getpass.getpass("New identity key password (12+ characters): ")
            issue_identity(
                args.root_key,
                args.root_cert,
                args.root_pin,
                root_password,
                args.key,
                args.cert,
                password,
                name=args.name,
                organization=args.organization,
            )
            print(
                "Certificate issued; issuance alone does not establish identity trust."
            )
        elif args.command == "seal":
            password = getpass.getpass("Signer key password: ")
            protect_file(
                args.source,
                args.destination,
                args.signer_key,
                args.signer_cert,
                args.recipient_cert,
                args.root_cert,
                args.root_pin,
                password,
            )
            print("Signed and encrypted package saved.")
        elif args.command == "open":
            password = getpass.getpass("Recipient key password: ")
            name = recover_file(
                args.source,
                args.destination,
                args.recipient_key,
                args.recipient_cert,
                args.root_cert,
                args.root_pin,
                password,
            )
            print(f"Verified and decrypted. Package document name: {name!r}")
    except (SecureDocError, OSError, ImportError) as exc:
        print(f"SecureDoc error: {exc}", file=sys.stderr)
        return 1
    return 0

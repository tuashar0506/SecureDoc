"""End-to-end CLI and disk workflows using temporary keys and documents."""

import json
import secrets
from pathlib import Path

import pytest

from securedoc.cli import main
from securedoc.services.workflows import (
    initialize_ca,
    issue_identity,
    protect_file,
    recover_file,
)
from securedoc.utils.exceptions import DocumentError


@pytest.fixture(scope="module")
def passwords() -> tuple[str, str, str]:
    return tuple(secrets.token_urlsafe(32) for _ in range(3))


def test_full_file_workflow(tmp_path: Path, passwords: tuple[str, str, str]) -> None:
    ca_pass, alice_pass, bob_pass = passwords
    root_key, root_cert = tmp_path / "root.key", tmp_path / "root.pem"
    pin = initialize_ca(root_key, root_cert, ca_pass)
    alice_key, alice_cert = tmp_path / "alice.key", tmp_path / "alice.pem"
    bob_key, bob_cert = tmp_path / "bob.key", tmp_path / "bob.pem"
    issue_identity(
        root_key,
        root_cert,
        pin,
        ca_pass,
        alice_key,
        alice_cert,
        alice_pass,
        name="Alice",
        organization="Demo",
    )
    issue_identity(
        root_key,
        root_cert,
        pin,
        ca_pass,
        bob_key,
        bob_cert,
        bob_pass,
        name="Bob",
        organization="Demo",
    )
    source = tmp_path / "report.txt"
    source.write_bytes(b"Test-only report\x00")
    package = tmp_path / "report.sdoc"
    protect_file(
        source, package, alice_key, alice_cert, bob_cert, root_cert, pin, alice_pass
    )
    assert source.read_bytes() == b"Test-only report\x00"
    assert b"Test-only report" not in package.read_bytes()
    output = tmp_path / "recovered.txt"
    with pytest.raises(DocumentError):
        recover_file(package, output, alice_key, bob_cert, root_cert, pin, alice_pass)
    assert not output.exists()
    body = json.loads(package.read_bytes())
    body["ciphertext"] = "AAAA"
    damaged = tmp_path / "damaged.sdoc"
    damaged.write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(DocumentError):
        recover_file(damaged, output, bob_key, bob_cert, root_cert, pin, bob_pass)
    assert not output.exists()
    with pytest.raises(DocumentError):
        recover_file(package, source, bob_key, bob_cert, root_cert, pin, bob_pass)
    assert source.read_bytes() == b"Test-only report\x00"
    name = recover_file(package, output, bob_key, bob_cert, root_cert, pin, bob_pass)
    assert name == "report.txt"
    assert output.read_bytes() == source.read_bytes()
    with pytest.raises(DocumentError):
        protect_file(
            source,
            tmp_path / "wrong.ext",
            alice_key,
            alice_cert,
            bob_cert,
            root_cert,
            pin,
            alice_pass,
        )


def test_cli_prompts_and_does_not_echo_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    password = secrets.token_urlsafe(32)
    monkeypatch.setattr("securedoc.cli.getpass.getpass", lambda _: password)
    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.pem"
    assert main(["init-ca", "--key", str(key), "--cert", str(cert)]) == 0
    assert key.exists() and cert.exists()
    output = capsys.readouterr()
    assert password not in output.out + output.err
    assert main(["fingerprint", str(cert)]) == 0
    assert "NOT trust" in capsys.readouterr().out


def test_cli_failure_does_not_write_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    password = secrets.token_urlsafe(32)
    monkeypatch.setattr("securedoc.cli.getpass.getpass", lambda _: password)
    target = tmp_path / "ca.key"
    args = ["init-ca", "--key", str(target), "--cert", str(tmp_path / "ca.pem")]
    assert main(args) == 0
    capsys.readouterr()
    assert main(args) == 1
    assert password not in capsys.readouterr().err


def test_cli_seal_and_open_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_pass, alice_pass, bob_pass = (secrets.token_urlsafe(32) for _ in range(3))
    root_key, root_cert = tmp_path / "root.key", tmp_path / "root.pem"
    pin = initialize_ca(root_key, root_cert, ca_pass)
    alice_key, alice_cert = tmp_path / "alice.key", tmp_path / "alice.pem"
    bob_key, bob_cert = tmp_path / "bob.key", tmp_path / "bob.pem"
    for name, key, cert, password in (
        ("Alice", alice_key, alice_cert, alice_pass),
        ("Bob", bob_key, bob_cert, bob_pass),
    ):
        issue_identity(
            root_key,
            root_cert,
            pin,
            ca_pass,
            key,
            cert,
            password,
            name=name,
            organization="Demo",
        )
    source, package, output = (
        tmp_path / "input.txt",
        tmp_path / "transfer.sdoc",
        tmp_path / "output.txt",
    )
    source.write_bytes(b"Generated test-only data")
    passwords = iter((alice_pass, bob_pass))
    monkeypatch.setattr("securedoc.cli.getpass.getpass", lambda _: next(passwords))
    assert (
        main(
            [
                "seal",
                str(source),
                str(package),
                "--signer-key",
                str(alice_key),
                "--signer-cert",
                str(alice_cert),
                "--recipient-cert",
                str(bob_cert),
                "--root-cert",
                str(root_cert),
                "--root-pin",
                pin,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "open",
                str(package),
                str(output),
                "--recipient-key",
                str(bob_key),
                "--recipient-cert",
                str(bob_cert),
                "--root-cert",
                str(root_cert),
                "--root-pin",
                pin,
            ]
        )
        == 0
    )
    assert output.read_bytes() == source.read_bytes()

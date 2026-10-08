"""In-memory X.509 issuance demo; does not persist private keys or trust a CA."""

from securedoc.crypto.certificates import (
    certificate_fingerprint,
    create_root_ca,
    issue_user_certificate,
)
from securedoc.crypto.key_manager import generate_rsa_private_key


def main() -> None:
    ca_key = generate_rsa_private_key()
    alice_key = generate_rsa_private_key()
    root = create_root_ca(ca_key)
    alice = issue_user_certificate(
        root,
        ca_key,
        alice_key.public_key(),
        common_name="Alice",
        organization="Demo University",
    )
    alice.verify_directly_issued_by(root)
    print("X.509 issuance signature verifies; trust is NOT established.")
    print("Alice certificate SHA-256 fingerprint:", certificate_fingerprint(alice))


if __name__ == "__main__":
    main()

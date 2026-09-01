"""Generate a password hash offline; never writes a credential file."""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import secrets


ROUNDS = 600_000


def encode_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ROUNDS)
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${ROUNDS}${salt_text}${digest_text}"


def main() -> None:
    first = getpass.getpass("New dashboard password: ")
    second = getpass.getpass("Repeat dashboard password: ")
    if not first or not hmac.compare_digest(first, second):
        raise SystemExit("Passwords are empty or do not match")
    print(encode_password(first))


if __name__ == "__main__":
    main()

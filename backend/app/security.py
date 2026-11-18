"""Password, session, and CSRF helpers."""

import base64
import hashlib
import hmac
import secrets

import argon2
from argon2.exceptions import VerificationError

_hasher = argon2.PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    """Verify a plaintext password against an Argon2id or legacy PBKDF2 hash."""
    if encoded.startswith("$argon2"):
        try:
            return _hasher.verify(encoded, password)
        except (VerificationError, Exception):
            return False

    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            base64.urlsafe_b64decode(salt.encode()),
            int(rounds),
        )
        return hmac.compare_digest(
            actual, base64.urlsafe_b64decode(expected.encode())
        )
    except (ValueError, TypeError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)

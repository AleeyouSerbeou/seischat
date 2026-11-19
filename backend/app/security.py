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


def new_csrf_token(secret: str | None = None) -> str:
    from datetime import datetime, timezone
    from app.core.config import get_settings

    key = secret or get_settings().secret_key
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    nonce = secrets.token_hex(16)
    data = f"{timestamp}.{nonce}"
    sig = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{data}.{sig}"


def is_valid_csrf_token(token: str, secret: str | None = None, max_age_seconds: int = 3600) -> bool:
    if not token or token.count(".") != 2:
        return False
    parts = token.split(".", 2)
    timestamp_str, nonce, sig = parts
    try:
        from datetime import datetime, timezone
        ts = int(timestamp_str)
        now = int(datetime.now(timezone.utc).timestamp())
        if now - ts > max_age_seconds or ts > now + 300:
            return False
    except ValueError:
        return False

    from app.core.config import get_settings
    key = secret or get_settings().secret_key
    data = f"{timestamp_str}.{nonce}"
    expected = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)

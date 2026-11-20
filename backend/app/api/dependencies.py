"""Shared request dependencies for authentication and CSRF protection."""

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.connection import get_db
from app.models import Session as UserSession, User
from app.security import token_hash


def is_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    settings = get_settings()
    session = None

    # 1. Primary: HttpOnly session cookie
    raw_token = request.cookies.get(settings.session_cookie_name)
    if raw_token:
        session = db.scalar(
            select(UserSession)
            .where(UserSession.token_hash == token_hash(raw_token))
            .where(UserSession.revoked_at.is_(None))
        )
        if session and is_expired(session.expires_at):
            session = None

    # 2. Secondary fallback: Authorization: Bearer token (for cross-site subdomains, mobile, or if cookie was invalid)
    if not session:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip()
            session = db.scalar(
                select(UserSession)
                .where(UserSession.token_hash == token_hash(bearer_token))
                .where(UserSession.revoked_at.is_(None))
            )
            if session and is_expired(session.expires_at):
                session = None

    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthenticated")
    return session.user


def require_csrf(request: Request) -> None:
    settings = get_settings()
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get("X-CSRF-Token")
    if not header_token:
        raise HTTPException(status_code=403, detail="csrf_failed")

    # 1. If cookie was preserved and delivered by the browser, verify double-submit match
    if cookie_token and len(cookie_token) == len(header_token):
        import hmac

        if hmac.compare_digest(cookie_token, header_token):
            return

    # 2. If cookie was dropped or overwritten (e.g., cross-site subdomain, Safari ITP,
    # or cookie collision), verify the cryptographic HMAC signature of the header token.
    from app.security import is_valid_csrf_token

    if not is_valid_csrf_token(header_token, settings.secret_key):
        raise HTTPException(status_code=403, detail="csrf_failed")

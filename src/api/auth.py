"""Minimal local authentication primitives for the thesis application."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.database import get_db
from src.api.models import User


SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_BYTES,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(derived).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, expected_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        parameters = (int(n), int(r), int(p))
        if parameters != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_text.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=parameters[0],
            r=parameters[1],
            p=parameters[2],
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Perform the same password work for an unknown email to reduce account-enumeration
# timing differences. This value is process-local and is never stored.
INVALID_PASSWORD_HASH = hash_password("invalid-account-placeholder")


@dataclass(frozen=True, slots=True)
class SessionRecord:
    user_id: int
    expires_at: datetime


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(request: Request, user_id: int) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=request.app.state.settings.auth_session_hours
    )
    request.app.state.auth_sessions[_token_digest(token)] = SessionRecord(
        user_id=user_id, expires_at=expires_at
    )
    return token, expires_at


def revoke_session(request: Request, token: str) -> None:
    request.app.state.auth_sessions.pop(_token_digest(token), None)


def _bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.casefold() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = _bearer_token(authorization)
    digest = _token_digest(token)
    session = request.app.state.auth_sessions.get(digest)
    now = datetime.now(timezone.utc)
    if session is None or session.expires_at <= now:
        request.app.state.auth_sessions.pop(digest, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.scalar(select(User).where(User.id == session.user_id))
    if user is None or not user.is_active:
        request.app.state.auth_sessions.pop(digest, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_session_token(authorization: str | None = Header(default=None)) -> str:
    return _bearer_token(authorization)

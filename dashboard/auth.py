"""Small, testable Streamlit authentication-state helpers."""

from collections.abc import MutableMapping
from typing import Any

from dashboard.api_client import APIError


TOKEN_KEY = "auth_access_token"
USER_KEY = "auth_user"
NOTICE_KEY = "auth_notice"
EXPIRED_MESSAGE = "Your session has expired. Please log in again."


def token_from(state: MutableMapping[str, Any]) -> str | None:
    value = state.get(TOKEN_KEY)
    return value if isinstance(value, str) and value else None


def current_user_from(state: MutableMapping[str, Any]) -> dict | None:
    value = state.get(USER_KEY)
    return value if isinstance(value, dict) else None


def store_login(state: MutableMapping[str, Any], result: dict) -> None:
    token = result.get("access_token")
    user = result.get("user")
    if not isinstance(token, str) or not token or not isinstance(user, dict):
        raise ValueError("Login response did not contain a valid session")
    state[TOKEN_KEY] = token
    state[USER_KEY] = user
    state.pop(NOTICE_KEY, None)


def clear_auth(state: MutableMapping[str, Any], message: str | None = None) -> None:
    state.pop(TOKEN_KEY, None)
    state.pop(USER_KEY, None)
    if message:
        state[NOTICE_KEY] = message


def require_login(state: MutableMapping[str, Any], client) -> dict | None:
    """Validate the local token and return the ADMIN identity, or clear it."""
    if token_from(state) is None:
        return None
    try:
        user = client.current_user()
    except APIError as exc:
        if exc.status_code in (401, 403):
            clear_auth(state, EXPIRED_MESSAGE)
            return None
        raise
    if user.get("role") != "ADMIN":
        clear_auth(state, "Administrator access is required.")
        return None
    state[USER_KEY] = user
    return user


def handle_auth_failure(state: MutableMapping[str, Any], exc: APIError) -> bool:
    if exc.status_code not in (401, 403):
        return False
    clear_auth(state, EXPIRED_MESSAGE)
    return True

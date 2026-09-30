"""Browser-side persistence for the Streamlit authentication session."""

from datetime import datetime, timezone

import extra_streamlit_components as stx


AUTH_COOKIE_NAME = "rf_nids_session"


def cookie_manager():
    """Return the browser cookie manager component."""
    return stx.CookieManager(key="rf_nids_cookie_manager")


def read_auth_cookie(manager) -> str | None:
    """Read the persisted RF-NIDS session token."""
    value = manager.get(AUTH_COOKIE_NAME)
    return value if isinstance(value, str) and value else None


def store_auth_cookie(manager, token: str, expires_at: str) -> None:
    """Persist the opaque backend session token until backend expiry."""
    expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    manager.set(
        AUTH_COOKIE_NAME,
        token,
        expires_at=expires,
        path="/",
        same_site="strict",
    )


def clear_auth_cookie(manager) -> None:
    """Remove the persisted authentication cookie."""
    manager.delete(AUTH_COOKIE_NAME)

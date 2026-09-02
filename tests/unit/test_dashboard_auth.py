import pytest

from dashboard.api_client import APIError
from dashboard.auth import (
    EXPIRED_MESSAGE,
    NOTICE_KEY,
    TOKEN_KEY,
    USER_KEY,
    clear_auth,
    handle_auth_failure,
    require_login,
    store_login,
    token_from,
)


class Client:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def current_user(self):
        if self.error:
            raise self.error
        return self.result


def test_login_state_round_trip_and_clear():
    state = {}
    store_login(state, {"access_token": "secret-token", "user": {"role": "ADMIN"}})
    assert token_from(state) == "secret-token"
    clear_auth(state)
    assert TOKEN_KEY not in state
    assert USER_KEY not in state


def test_page_guard_accepts_admin_and_refreshes_identity():
    state = {TOKEN_KEY: "token", USER_KEY: {"name": "Old"}}
    user = {"name": "Admin", "email": "admin@example.test", "role": "ADMIN"}
    assert require_login(state, Client(result=user)) == user
    assert state[USER_KEY] == user


@pytest.mark.parametrize("status", [401, 403])
def test_page_guard_clears_invalid_or_forbidden_session(status):
    state = {TOKEN_KEY: "token", USER_KEY: {"role": "ADMIN"}}
    assert require_login(state, Client(error=APIError("denied", status))) is None
    assert token_from(state) is None
    assert state[NOTICE_KEY] == EXPIRED_MESSAGE


def test_page_guard_preserves_session_on_api_outage():
    state = {TOKEN_KEY: "token", USER_KEY: {"role": "ADMIN"}}
    with pytest.raises(APIError):
        require_login(state, Client(error=APIError("offline")))
    assert token_from(state) == "token"


def test_auth_failure_helper_only_clears_authorization_failures():
    state = {TOKEN_KEY: "token", USER_KEY: {"role": "ADMIN"}}
    assert not handle_auth_failure(state, APIError("offline"))
    assert token_from(state) == "token"
    assert handle_auth_failure(state, APIError("expired", 401))
    assert token_from(state) is None

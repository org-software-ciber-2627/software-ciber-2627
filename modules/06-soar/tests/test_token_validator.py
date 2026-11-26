from __future__ import annotations

import http.client
import json
import urllib.error
from io import BytesIO

import pytest

from soar.models.identity import AuthenticatedUser
from soar.services.token_validator import (
    IdentityUnavailableError,
    TokenValidator,
    UnauthorizedError,
    identity_url_from_env,
)


class _Response:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def test_validate_returns_user_and_sends_bearer_token() -> None:
    seen = []

    def opener(request, timeout):
        seen.append((request, timeout))
        return _Response(
            200,
            {"valid": True, "user_id": 42, "username": " analista ", "role": " analista "},
        )

    user = TokenValidator("http://identity/", opener=opener).validate("secret-token")

    assert user == AuthenticatedUser(user_id=42, username="analista", role="analista")
    request, timeout = seen[0]
    assert request.full_url == "http://identity/auth/validate"
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert timeout == 5.0


def test_validate_maps_identity_rejection_to_unauthorized(caplog) -> None:
    def opener(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "unauthorized",
            None,
            BytesIO(b""),
        )

    with pytest.raises(UnauthorizedError):
        TokenValidator("http://identity", opener=opener).validate("secret-token")
    assert "secret-token" not in caplog.text


def test_validate_maps_valid_false_to_unauthorized() -> None:
    with pytest.raises(UnauthorizedError):
        TokenValidator(
            "http://identity",
            opener=lambda request, timeout: _Response(200, {"valid": False}),
        ).validate("secret-token")


def test_validate_maps_identity_failure_to_unavailable() -> None:
    def opener(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            503,
            "unavailable",
            None,
            BytesIO(b""),
        )

    with pytest.raises(IdentityUnavailableError):
        TokenValidator("http://identity", opener=opener).validate("secret-token")


def test_validate_maps_remote_disconnected_to_unavailable() -> None:
    def opener(request, timeout):
        raise http.client.RemoteDisconnected("identity disconnected")

    with pytest.raises(IdentityUnavailableError):
        TokenValidator("http://identity", opener=opener).validate("secret-token")


@pytest.mark.parametrize(
    "payload",
    [
        {"valid": True, "user_id": 1, "role": "analista"},
        {"valid": True, "user_id": 1, "username": "analista"},
        {"valid": True, "user_id": [], "username": "analista", "role": "analista"},
    ],
)
def test_validate_maps_incomplete_user_to_unavailable(payload: dict[str, object]) -> None:
    with pytest.raises(IdentityUnavailableError):
        TokenValidator(
            "http://identity",
            opener=lambda request, timeout: _Response(200, payload),
        ).validate("secret-token")


def test_identity_url_is_read_from_environment_each_time(monkeypatch) -> None:
    monkeypatch.setenv("AUTH_URL", "http://identity/auth/")
    assert identity_url_from_env() == "http://identity/auth"

    monkeypatch.setenv("AUTH_URL", "")
    monkeypatch.setenv("IDENTITY_URL", "http://fallback/")
    assert identity_url_from_env() == "http://fallback"

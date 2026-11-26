from __future__ import annotations

import pytest

import app as soar_app
from soar.models.identity import AuthenticatedUser


def test_request_identity_uses_authenticated_username_and_ignores_body() -> None:
    user = AuthenticatedUser(user_id=1, username="  analista.real  ", role="analista")

    assert soar_app.request_identity({"changed_by": 42}, user) == "analista.real"


def test_request_identity_rejects_authenticated_username_over_limit() -> None:
    user = AuthenticatedUser(user_id=1, username="a" * 101, role="analista")

    with pytest.raises(ValueError, match="changed_by no puede superar 100 caracteres"):
        soar_app.request_identity({"changed_by": "analista"}, user)


def test_request_identity_keeps_body_validation_without_authentication() -> None:
    assert soar_app.request_identity({"changed_by": "  analista  "}, None) == "analista"

    with pytest.raises(ValueError, match="changed_by debe ser texto"):
        soar_app.request_identity({"changed_by": 42}, None)

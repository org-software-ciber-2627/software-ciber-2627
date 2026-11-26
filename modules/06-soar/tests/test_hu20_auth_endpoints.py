from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import app as soar_app


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class _IdentityHandler(BaseHTTPRequestHandler):
    calls = 0
    authorization_headers: list[str] = []
    users = {
        "tok-analista": {
            "valid": True,
            "user_id": 1,
            "username": "ana.analista",
            "role": "analista",
        },
        "tok-admin": {
            "valid": True,
            "user_id": 2,
            "username": "root.admin",
            "role": "admin",
        },
        "tok-servicio": {
            "valid": True,
            "user_id": 3,
            "username": "svc-dashboard",
            "role": "servicio",
        },
        "tok-raro": {
            "valid": True,
            "user_id": 4,
            "username": "x",
            "role": "invitado",
        },
    }

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/auth/validate":
            self._send_json(404, {"error": "not_found"})
            return

        type(self).calls += 1
        authorization = self.headers.get("Authorization", "")
        type(self).authorization_headers.append(authorization)
        token = authorization.removeprefix("Bearer ")

        if token == "tok-lento":
            time.sleep(1)
            self._send_json(
                200,
                {
                    "valid": True,
                    "user_id": 5,
                    "username": "slow.user",
                    "role": "analista",
                },
            )
        elif token == "tok-500":
            self._send_json(500, {"error": "identity_error"})
        elif token == "tok-invalido":
            self._send_json(401, {"error": "invalid_token", "valid": False})
        elif token in type(self).users:
            self._send_json(200, type(self).users[token])
        else:
            self._send_json(401, {"error": "invalid_token", "valid": False})

    def log_message(self, format: str, *args: Any) -> None:
        return


def _start_server(
    handler: type[BaseHTTPRequestHandler],
) -> tuple[_Server, threading.Thread, str]:
    server = _Server(("127.0.0.1", 0), handler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _stop_server(server: _Server, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def soar_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _IdentityHandler.calls = 0
    _IdentityHandler.authorization_headers = []
    identity_server, identity_thread, identity_url = _start_server(_IdentityHandler)

    monkeypatch.setenv("AUTH_URL", identity_url)
    database_path = tmp_path / "hu20.db"
    monkeypatch.setattr(soar_app, "DATABASE_PATH", str(database_path))

    original_init = soar_app.TokenValidator.__init__

    def fast_validator_init(
        validator,
        url: str,
        timeout: float = 5.0,
        opener=urllib.request.urlopen,
    ) -> None:
        original_init(validator, url, timeout=0.5, opener=opener)

    monkeypatch.setattr(soar_app.TokenValidator, "__init__", fast_validator_init)

    mock_path = Path(__file__).parents[1] / "mocks" / "alertas_mock.json"
    mock_alerts = json.loads(mock_path.read_text(encoding="utf-8"))["alerts"]
    brute_force_alert = next(
        alert for alert in mock_alerts if alert["event_type"] == "fuerza_bruta"
    )
    monkeypatch.setattr(soar_app, "fetch_alerts", lambda: [brute_force_alert])
    soar_app.poll_siem()
    incident_id = soar_app.list_incidents()[0]["incident_id"]

    # Keep authorized POST /poll independent from the external SIEM.
    monkeypatch.setattr(soar_app, "fetch_alerts", lambda: [])
    soar_server, soar_thread, base_url = _start_server(soar_app.SoarHandler)

    def request(
        method: str,
        path: str,
        token: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        headers = {}
        if token is not None:
            headers["Authorization"] = (
                token if token.lower().startswith(("basic ", "bearer")) else f"Bearer {token}"
            )
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request_obj = urllib.request.Request(
            f"{base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            response = urllib.request.urlopen(request_obj, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status, payload

    try:
        yield request, incident_id, identity_url
    finally:
        _stop_server(soar_server, soar_thread)
        _stop_server(identity_server, identity_thread)


def _protected_endpoints(incident_id: str) -> list[tuple[str, str, dict[str, Any] | None]]:
    gets = [
        ("GET", "/incidents", None),
        ("GET", f"/incidents/{incident_id}/responses", None),
        ("GET", f"/incidents/{incident_id}/history", None),
        ("GET", "/metrics", None),
    ]
    # TODO: add GET /blacklist when HU19.4 exposes it in app.py.
    posts = [
        (
            "POST",
            f"/incidents/{incident_id}/status",
            {"status": "in_progress", "justification": "Prueba de permisos"},
        ),
        ("POST", "/poll", {}),
    ]
    return gets + posts


def test_missing_or_malformed_authorization_returns_401_for_all_protected_endpoints(
    soar_api,
) -> None:
    request, incident_id, _ = soar_api
    for method, path, body in _protected_endpoints(incident_id):
        for token in (None, "Basic xxx", "Bearer "):
            status, payload = request(method, path, token=token, body=body)
            assert status == 401
            assert payload == {"error": "unauthorized"}


def test_invalid_token_returns_401(soar_api) -> None:
    request, incident_id, _ = soar_api

    status, payload = request("GET", f"/incidents/{incident_id}/history", "tok-invalido")

    assert status == 401
    assert payload == {"error": "unauthorized"}


def test_health_is_public_when_identity_is_unavailable(soar_api, monkeypatch) -> None:
    request, _, _ = soar_api
    monkeypatch.setenv("AUTH_URL", "http://127.0.0.1:1")

    status, payload = request("GET", "/health")

    assert status == 200
    assert payload == {"status": "ok", "module": "06-soar"}


@pytest.mark.parametrize(
    ("token", "write_allowed"),
    [("tok-analista", True), ("tok-admin", True), ("tok-servicio", False)],
)
def test_allowed_roles_can_read_and_write_as_per_contract(
    soar_api, token: str, write_allowed: bool
) -> None:
    request, incident_id, _ = soar_api
    for method, path, body in _protected_endpoints(incident_id):
        status, _ = request(method, path, token=token, body=body)
        if method == "GET" or write_allowed:
            assert status == 200
        else:
            assert status == 403


def test_guest_role_is_forbidden_from_all_protected_endpoints(soar_api) -> None:
    request, incident_id, _ = soar_api
    for method, path, body in _protected_endpoints(incident_id):
        status, payload = request(method, path, "tok-raro", body)
        assert status == 403
        assert payload == {"error": "forbidden"}


def test_identity_unavailable_never_returns_401_or_endpoint_data(
    soar_api, monkeypatch
) -> None:
    request, incident_id, identity_url = soar_api
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    monkeypatch.setenv("AUTH_URL", f"http://127.0.0.1:{closed_port}")

    status, payload = request("GET", "/incidents", "tok-analista")

    assert status == 503
    assert payload == {"error": "identity_unavailable"}
    monkeypatch.setenv("AUTH_URL", identity_url)

    for token in ("tok-500", "tok-lento"):
        status, payload = request("GET", f"/incidents/{incident_id}/history", token)
        assert status == 503
        assert payload == {"error": "identity_unavailable"}


def test_authentication_precedes_incident_not_found(soar_api) -> None:
    request, _, _ = soar_api

    status, payload = request("GET", "/incidents/INC-NOEXISTE/history")
    assert status == 401
    assert payload == {"error": "unauthorized"}

    status, payload = request(
        "GET", "/incidents/INC-NOEXISTE/history", "tok-analista"
    )
    assert status == 404
    assert payload == {"error": "incident_not_found"}


def test_changed_by_comes_from_token_and_automatic_changes_keep_actor(soar_api) -> None:
    request, incident_id, _ = soar_api
    status, response = request(
        "POST",
        f"/incidents/{incident_id}/status",
        "tok-analista",
        {
            "status": "closed",
            "justification": "Cierre autenticado",
            "resolution_reason": "Prueba completada",
            "changed_by": "otra.persona",
        },
    )
    assert status == 200
    assert response["changed_by"] == "ana.analista"

    status, history = request(
        "GET", f"/incidents/{incident_id}/history", "tok-analista"
    )
    assert status == 200
    closing_change = next(change for change in history if change["to_status"] == "closed")
    assert closing_change["changed_by"] == "ana.analista"
    automatic_changes = [
        change
        for change in history
        if change["changed_by"] == "soar-automation"
    ]
    assert automatic_changes


def test_authenticated_close_does_not_require_changed_by_in_body(soar_api) -> None:
    request, incident_id, _ = soar_api

    status, response = request(
        "POST",
        f"/incidents/{incident_id}/status",
        "tok-analista",
        {
            "status": "closed",
            "justification": "Cierre autenticado",
            "resolution_reason": "Prueba completada",
        },
    )

    assert status == 200
    assert response["changed_by"] == "ana.analista"


def test_authenticated_non_string_changed_by_is_ignored(soar_api) -> None:
    request, incident_id, _ = soar_api

    status, response = request(
        "POST",
        f"/incidents/{incident_id}/status",
        "tok-analista",
        {
            "status": "in_progress",
            "justification": "Cambio autenticado",
            "changed_by": 123,
        },
    )

    assert status == 200
    assert response["changed_by"] == "ana.analista"


def test_endpoints_remain_open_without_identity_url_and_warn_once(
    soar_api, monkeypatch, caplog
) -> None:
    request, _, _ = soar_api
    monkeypatch.delenv("AUTH_URL", raising=False)
    monkeypatch.delenv("IDENTITY_URL", raising=False)
    monkeypatch.setattr(soar_app, "_auth_warning_emitted", False)
    caplog.set_level("WARNING", logger="soar")

    status, _ = request("GET", "/incidents")
    assert status == 200
    request("GET", "/metrics")

    assert caplog.text.count(
        "AUTH_URL no configurada: endpoints del SOAR sin autenticación"
    ) == 1


def test_auth_tokens_are_not_logged_and_validation_has_no_cache(
    soar_api, caplog
) -> None:
    request, incident_id, _ = soar_api
    _IdentityHandler.calls = 0
    _IdentityHandler.authorization_headers = []
    caplog.set_level("DEBUG")

    first_status, _ = request("GET", "/metrics", "tok-analista")
    second_status, _ = request("GET", "/metrics", "tok-analista")
    assert _IdentityHandler.calls == 2
    assert _IdentityHandler.authorization_headers == [
        "Bearer tok-analista",
        "Bearer tok-analista",
    ]

    failure_status, _ = request("GET", f"/incidents/{incident_id}/history", "tok-500")

    assert first_status == second_status == 200
    assert failure_status == 503
    assert _IdentityHandler.calls == 3
    assert _IdentityHandler.authorization_headers == [
        "Bearer tok-analista",
        "Bearer tok-analista",
        "Bearer tok-500",
    ]
    assert "tok-analista" not in caplog.text
    assert "tok-500" not in caplog.text

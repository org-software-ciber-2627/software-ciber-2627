from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import app as soar_app
from soar.services.auth_client import AuthClientError, IdentityAuthClient


class _MockEcosystemHandler(BaseHTTPRequestHandler):
    login_calls = 0
    alerts_calls = 0
    valid_token = "jwt-token-inicial"
    force_503 = False
    always_401 = False
    login_429 = False

    def _send_json(self, status: int, body: dict | list) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        if self.path == "/auth/login":
            type(self).login_calls += 1
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if type(self).login_429:
                self._send_json(429, {"error": "too_many_attempts"})
            elif body.get("username") == "svc-soar" and body.get("password") == "clave-test-segura":
                token = "jwt-token-renovado" if type(self).login_calls > 1 else "jwt-token-inicial"
                type(self).valid_token = token
                self._send_json(200, {"access_token": token, "token_type": "bearer"})
            else:
                self._send_json(401, {"error": "invalid_credentials"})
        else:
            self._send_json(404, {"error": "not_found"})

    def do_GET(self) -> None:
        if self.path == "/alerts":
            type(self).alerts_calls += 1
            if type(self).force_503:
                self._send_json(503, {"error": "siem_unavailable"})
                return
            auth_header = self.headers.get("Authorization", "")
            if type(self).always_401 or auth_header != f"Bearer {type(self).valid_token}":
                self._send_json(401, {"error": "unauthorized"})
                return
            self._send_json(200, [{"alert_id": "AL-AUTH-1", "event_type": "port_scan"}])
        else:
            self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args) -> None:
        return


def _start_mock_server() -> tuple[ThreadingHTTPServer, str]:
    _MockEcosystemHandler.login_calls = 0
    _MockEcosystemHandler.alerts_calls = 0
    _MockEcosystemHandler.valid_token = "jwt-token-inicial"
    _MockEcosystemHandler.force_503 = False
    _MockEcosystemHandler.always_401 = False
    _MockEcosystemHandler.login_429 = False

    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockEcosystemHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def test_fetch_alerts_authenticates_and_reuses_cached_token(monkeypatch) -> None:
    server, base_url = _start_mock_server()
    try:
        client = IdentityAuthClient(auth_url=base_url, username="svc-soar", password="clave-test-segura")
        monkeypatch.setattr(soar_app, "AUTH_CLIENT", client)
        monkeypatch.setattr(soar_app, "SIEM_URL", base_url)

        first = soar_app.fetch_alerts()
        second = soar_app.fetch_alerts()

        assert len(first) == 1
        assert first[0]["alert_id"] == "AL-AUTH-1"
        assert len(second) == 1
        assert _MockEcosystemHandler.login_calls == 1
        assert _MockEcosystemHandler.alerts_calls == 2
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_alerts_refreshes_token_once_on_401(monkeypatch) -> None:
    server, base_url = _start_mock_server()
    try:
        client = IdentityAuthClient(auth_url=base_url, username="svc-soar", password="clave-test-segura")
        # Simulamos un token caducado en caché
        client._token = "jwt-token-caducado"
        client._expires_at = 9999999999.0

        monkeypatch.setattr(soar_app, "AUTH_CLIENT", client)
        monkeypatch.setattr(soar_app, "SIEM_URL", base_url)

        alerts = soar_app.fetch_alerts()

        assert len(alerts) == 1
        assert _MockEcosystemHandler.login_calls == 1
        assert _MockEcosystemHandler.alerts_calls == 2
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_alerts_raises_on_persistent_401_without_looping(monkeypatch) -> None:
    server, base_url = _start_mock_server()
    _MockEcosystemHandler.always_401 = True
    try:
        client = IdentityAuthClient(auth_url=base_url, username="svc-soar", password="clave-test-segura")
        monkeypatch.setattr(soar_app, "AUTH_CLIENT", client)
        monkeypatch.setattr(soar_app, "SIEM_URL", base_url)

        with pytest.raises(RuntimeError, match="HTTP 401"):
            soar_app.fetch_alerts()

        # Solo 1 login inicial + 1 reintento tras el primer 401 (nunca 5 intentos que disparen 429)
        assert _MockEcosystemHandler.login_calls == 2
        assert _MockEcosystemHandler.alerts_calls == 2
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_alerts_raises_on_503_instead_of_returning_empty_list(monkeypatch) -> None:
    server, base_url = _start_mock_server()
    _MockEcosystemHandler.force_503 = True
    try:
        client = IdentityAuthClient(auth_url=base_url, username="svc-soar", password="clave-test-segura")
        monkeypatch.setattr(soar_app, "AUTH_CLIENT", client)
        monkeypatch.setattr(soar_app, "SIEM_URL", base_url)

        with pytest.raises(RuntimeError, match="HTTP 503"):
            soar_app.fetch_alerts()
    finally:
        server.shutdown()
        server.server_close()


def test_auth_client_fails_cleanly_when_env_vars_missing() -> None:
    client = IdentityAuthClient(auth_url="", username="svc-soar", password="")
    with pytest.raises(AuthClientError):
        client.get_token()


class _FakeClock:
    """Reloj monotónico controlado por el test (sin sleep)."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _client(base_url: str, clock: _FakeClock, password: str = "clave-test-segura") -> IdentityAuthClient:
    return IdentityAuthClient(
        auth_url=base_url, username="svc-soar", password=password, retry_seconds=300, clock=clock
    )


@pytest.mark.parametrize("login_429", [False, True], ids=["401", "429"])
def test_rejected_login_is_not_retried_until_the_wait_is_over(login_429) -> None:
    server, base_url = _start_mock_server()
    _MockEcosystemHandler.login_429 = login_429
    try:
        clock = _FakeClock()
        client = _client(base_url, clock, password="clave-incorrecta")

        with pytest.raises(AuthClientError, match="HTTP 429" if login_429 else "HTTP 401"):
            client.get_token()
        assert _MockEcosystemHandler.login_calls == 1

        # Durante la espera no se llama a Identidad
        clock.now += 299
        with pytest.raises(AuthClientError, match="no se reintenta"):
            client.get_token()
        with pytest.raises(AuthClientError, match="no se reintenta"):
            client.get_token(force_refresh=True)
        assert _MockEcosystemHandler.login_calls == 1

        # Pasada la espera, se vuelve a intentar el login
        clock.now += 2
        with pytest.raises(AuthClientError, match="HTTP"):
            client.get_token()
        assert _MockEcosystemHandler.login_calls == 2
    finally:
        server.shutdown()
        server.server_close()


def test_successful_login_after_the_wait_clears_it() -> None:
    server, base_url = _start_mock_server()
    try:
        clock = _FakeClock()
        client = _client(base_url, clock, password="clave-incorrecta")
        with pytest.raises(AuthClientError):
            client.get_token()

        clock.now += 301
        client.password = "clave-test-segura"
        assert client.get_token() == "jwt-token-renovado"

        # Sin espera pendiente: un nuevo login forzado llama a Identidad
        client.get_token(force_refresh=True)
        assert _MockEcosystemHandler.login_calls == 3
    finally:
        server.shutdown()
        server.server_close()


def test_network_error_on_login_does_not_start_the_wait(monkeypatch) -> None:
    calls = []

    def unreachable(request, timeout):
        # Error de red, no un rechazo de credenciales
        calls.append(request.full_url)
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", unreachable)
    client = _client("http://identidad", _FakeClock())

    for _ in range(2):
        with pytest.raises(AuthClientError, match="No se pudo conectar"):
            client.get_token()
    assert calls == ["http://identidad/auth/login"] * 2


def test_fetch_alerts_does_not_call_identity_during_the_wait(monkeypatch) -> None:
    server, base_url = _start_mock_server()
    try:
        clock = _FakeClock()
        client = _client(base_url, clock, password="clave-incorrecta")
        monkeypatch.setattr(soar_app, "AUTH_CLIENT", client)
        monkeypatch.setattr(soar_app, "SIEM_URL", base_url)

        for _ in range(3):
            with pytest.raises(RuntimeError):
                soar_app.fetch_alerts()

        assert _MockEcosystemHandler.login_calls == 1
        assert _MockEcosystemHandler.alerts_calls == 0
    finally:
        server.shutdown()
        server.server_close()


def test_retry_seconds_comes_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("SOAR_AUTH_RETRY_SECONDS", "60")
    assert IdentityAuthClient(auth_url="http://x", password="p").retry_seconds == 60

    monkeypatch.delenv("SOAR_AUTH_RETRY_SECONDS")
    assert IdentityAuthClient(auth_url="http://x", password="p").retry_seconds == 300

    monkeypatch.setenv("SOAR_AUTH_RETRY_SECONDS", "no-es-un-numero")
    assert IdentityAuthClient(auth_url="http://x", password="p").retry_seconds == 300
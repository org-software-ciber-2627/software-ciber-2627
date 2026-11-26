from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


from soar.models.identity import AuthenticatedUser
from soar.repositories.incident_repository import SqliteIncidentRepository
from soar.services.auth_client import AuthClientError, IdentityAuthClient
from soar.services.metrics_service import MetricsService
from soar.services.pipeline import IncidentNotFoundError, SoarPipeline
from soar.services.status_service import (
    IncidentClosedError,
    InvalidTransitionError,
    MissingJustificationError,
    MissingResolutionReasonError,
)
from soar.services.token_validator import (
    IdentityUnavailableError,
    TokenValidator,
    UnauthorizedError,
    identity_url_from_env,
)


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soar")

DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/soar.db")
SIEM_URL = os.getenv("SIEM_URL") or os.getenv("SIEM_API_URL") or "http://siem:80"
SIEM_URL = SIEM_URL.rstrip("/").removesuffix("/alerts")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", os.getenv("SOAR_POLLING_INTERVAL", "0")))
AUTH_CLIENT = IdentityAuthClient()
READ_ROLES = {"analista", "admin", "servicio"}
WRITE_ROLES = {"analista", "admin"}
_auth_warning_lock = threading.Lock()
_auth_warning_emitted = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def alert_key(alert: dict[str, Any]) -> str:
    explicit_id = alert.get("alert_id") or alert.get("id")
    if explicit_id is not None:
        return str(explicit_id)

    source_ip = alert.get("IP_origen", alert.get("ip_origen", alert.get("source_ip", "")))
    event_type = alert.get("tipo_evento", alert.get("event_type", ""))
    timestamp = alert.get("timestamp", "")
    raw_key = f"{source_ip}|{event_type}|{timestamp}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def connect_database() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_key TEXT NOT NULL UNIQUE,
            alert_json TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def save_alert(alert: dict[str, Any]) -> bool:
    key = alert_key(alert)
    connection = connect_database()
    try:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO incidents (alert_key, alert_json, first_seen)
            VALUES (?, ?, ?)
            """,
            (key, json.dumps(alert, sort_keys=True), utc_now()),
        )
        connection.commit()
        if cursor.rowcount == 0:
            logger.info("Alerta duplicada ignorada: %s", key)
            return False
        return True
    finally:
        connection.close()


def build_pipeline() -> SoarPipeline:
    return SoarPipeline(DATABASE_PATH, register_alert=save_alert, alert_key=alert_key)


def get_metrics() -> dict[str, Any]:
    repository = SqliteIncidentRepository(DATABASE_PATH)
    return MetricsService(repository).calculate_metrics().model_dump(mode="json")


# Campos añadidos en el Sprint 2; las filas anteriores sin Incident normalizado los devuelven vacíos
EMPTY_INCIDENT_VIEW = {
    "incident_id": None,
    "alert_id": None,
    "event_type": None,
    "severity": None,
    "priority": None,
    "source_ip": None,
    "status": None,
    "created_at": None,
    "resolved_at": None,
    "applied_playbook": None,
    "automation": None,
    "responses": [],
}

# SB-70 (HU12.1): Campos sensibles a enmascarar dentro de alert al exponer GET /incidents
SENSITIVE_ALERT_KEYS = {"credential", "username"}
MASKED_VALUE = "***"


def sanitize_alert(data: Any) -> Any:
    """Enmascara recursivamente credential y username dentro de alert sin mutar el origen."""
    if isinstance(data, dict):
        return {
            key: (MASKED_VALUE if key.lower() in SENSITIVE_ALERT_KEYS and value is not None else sanitize_alert(value))
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [sanitize_alert(item) for item in data]
    return data


def list_incidents() -> list[dict[str, Any]]:
    connection = connect_database()
    try:
        rows = connection.execute(
            "SELECT id, alert_key, alert_json, first_seen FROM incidents ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    views = build_pipeline().incident_views()
    return [
        {
            "id": row["id"],
            "alert_key": row["alert_key"],
            "alert": sanitize_alert(json.loads(row["alert_json"])),
            "first_seen": row["first_seen"],
            **views.get(row["alert_key"], EMPTY_INCIDENT_VIEW),
        }
        for row in rows
    ]


def _request_siem_alerts(token: str | None) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{SIEM_URL}/alerts", headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_alerts() -> list[dict[str, Any]]:
    try:
        token = AUTH_CLIENT.get_token() if AUTH_CLIENT.is_configured else None
        try:
            payload = _request_siem_alerts(token)
        except urllib.error.HTTPError as error:
            if error.code == 401 and AUTH_CLIENT.is_configured:
                logger.warning("SIEM devolvió 401; renovando token de servicio y reintentando una vez")
                AUTH_CLIENT.invalidate_token()
                refreshed_token = AUTH_CLIENT.get_token(force_refresh=True)
                payload = _request_siem_alerts(refreshed_token)
            else:
                raise
    except AuthClientError as error:
        logger.error("Fallo de autenticación al consultar el SIEM: %s", error)
        raise RuntimeError(str(error)) from error
    except urllib.error.HTTPError as error:
        logger.error("El SIEM respondió con error HTTP %s: %s", error.code, error)
        raise RuntimeError(f"El SIEM devolvió HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        logger.error("No se pudieron consultar las alertas del SIEM: %s", error)
        raise RuntimeError("No se pudieron consultar las alertas del SIEM") from error

    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        alerts = payload["alerts"]
    else:
        raise RuntimeError("La respuesta del SIEM no contiene una lista de alertas")

    if not all(isinstance(alert, dict) for alert in alerts):
        raise RuntimeError("El SIEM devolvio una alerta con formato invalido")
    return alerts


def poll_siem() -> dict[str, int]:
    alerts = fetch_alerts()
    pipeline = build_pipeline()
    result = {"received": len(alerts), "created": 0, "ignored": 0, "rejected": 0, "automated": 0}
    for alert in alerts:
        outcome = pipeline.process_alert(alert)
        result[outcome["result"]] += 1
        result["automated"] += outcome["automated"]
    logger.info("Sondeo completado: %s", result)
    return result


RESPONSES_PATH = re.compile(r"^/incidents/([^/]+)/responses$")
HISTORY_PATH = re.compile(r"^/incidents/([^/]+)/history$")
STATUS_PATH = re.compile(r"^/incidents/([^/]+)/status$")
# Campos de cada cambio que expone GET /incidents/{id}/history (HU7)
HISTORY_FIELDS = {"from_status", "to_status", "justification", "resolution_reason", "changed_by", "changed_at"}
STATUS_ERRORS = (
    IncidentClosedError,
    InvalidTransitionError,
    MissingJustificationError,
    MissingResolutionReasonError,
    ValueError,
)
MAX_CHANGED_BY_LENGTH = 100


def request_identity(body: dict[str, Any]) -> str | None:
    """
    Devuelve quién hace el cambio de estado (changed_by), sin espacios al principio ni al final,
    o None si no viene. Lanza ValueError si no es texto o supera MAX_CHANGED_BY_LENGTH.
    """
    # Hoy sale del cuerpo JSON; más adelante vendrá del token del Módulo 1 (grupo 1).
    value = body.get("changed_by")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("changed_by debe ser texto")
    value = value.strip()
    if len(value) > MAX_CHANGED_BY_LENGTH:
        raise ValueError(f"changed_by no puede superar {MAX_CHANGED_BY_LENGTH} caracteres")
    return value or None


class SoarHandler(BaseHTTPRequestHandler):
    def authenticate(
        self,
        allowed_roles: set[str],
    ) -> tuple[bool, AuthenticatedUser | None]:
        self.current_user: AuthenticatedUser | None = None
        path = urlparse(self.path).path
        if self.command == "GET" and path == "/health":
            return True, None

        identity_url = identity_url_from_env()
        if not identity_url:
            warn_authentication_disabled()
            return True, None

        authorization = self.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token.strip():
            self.send_json(401, {"error": "unauthorized"})
            return False, None

        try:
            user = TokenValidator(identity_url).validate(token.strip())
        except UnauthorizedError:
            self.send_json(401, {"error": "unauthorized"})
            return False, None
        except IdentityUnavailableError:
            self.send_json(503, {"error": "identity_unavailable"})
            return False, None

        if user.role not in allowed_roles:
            self.send_json(403, {"error": "forbidden"})
            return False, None

        self.current_user = user
        return True, user

    def send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        try:
            authenticated, _ = self.authenticate(READ_ROLES)
            if not authenticated:
                return
            self.handle_get(urlparse(self.path).path)
        except Exception:
            logger.exception("Error no previsto en GET %s", self.path)
            self.send_json(500, {"error": "internal_error"})

    def do_POST(self) -> None:
        try:
            authenticated, _ = self.authenticate(WRITE_ROLES)
            if not authenticated:
                return
            self.handle_post(urlparse(self.path).path)
        except Exception:
            logger.exception("Error no previsto en POST %s", self.path)
            self.send_json(500, {"error": "internal_error"})

    def handle_get(self, path: str) -> None:
        responses_match = RESPONSES_PATH.match(path)
        history_match = HISTORY_PATH.match(path)
        if path == "/health":
            self.send_json(200, {"status": "ok", "module": "06-soar"})
        elif path == "/incidents":
            self.send_json(200, list_incidents())
        elif path == "/metrics":
            self.send_json(200, get_metrics())
        elif responses_match:
            try:
                responses = build_pipeline().list_responses(responses_match.group(1))
            except IncidentNotFoundError:
                self.send_json(404, {"error": "incident_not_found"})
                return
            self.send_json(200, [response.model_dump(mode="json") for response in responses])
        elif history_match:
            try:
                history = build_pipeline().get_history(history_match.group(1))
            except IncidentNotFoundError:
                self.send_json(404, {"error": "incident_not_found"})
                return
            self.send_json(200, [change.model_dump(mode="json", include=HISTORY_FIELDS) for change in history])
        else:
            self.send_json(404, {"error": "not_found"})

    def handle_post(self, path: str) -> None:
        status_match = STATUS_PATH.match(path)
        if path == "/poll":
            try:
                self.send_json(200, poll_siem())
            except RuntimeError as error:
                logger.error("Sondeo fallido, se devuelve 502: %s", error)
                self.send_json(502, {"error": str(error)})
        elif status_match:
            self.change_status(status_match.group(1))
        else:
            self.send_json(404, {"error": "not_found"})

    def change_status(self, incident_id: str) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self.send_json(400, {"error": "El cuerpo debe ser JSON válido"})
            return
        if not isinstance(body, dict) or "status" not in body:
            self.send_json(400, {"error": "Faltan los campos status y justification"})
            return
        if not isinstance(body.get("justification") or "", str) or not isinstance(body.get("resolution_reason") or "", str):
            self.send_json(400, {"error": "justification y resolution_reason deben ser texto"})
            return
        pipeline = build_pipeline()
        try:
            # El 404 tiene prioridad sobre cualquier error de changed_by
            pipeline.get_incident(incident_id)
            try:
                changed_by = request_identity(body)
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
                return
            # HU7: cerrar exige saber quién lo cierra; se comprueba antes de tocar el incidente
            if body["status"] == "closed" and changed_by is None:
                self.send_json(400, {"error": "changed_by es obligatorio para cerrar un incidente"})
                return
            incident = pipeline.change_status(
                incident_id,
                body["status"],
                body.get("justification") or "",
                body.get("resolution_reason"),
                changed_by,
            )
        except IncidentNotFoundError:
            self.send_json(404, {"error": "incident_not_found"})
            return
        except STATUS_ERRORS as error:
            self.send_json(400, {"error": str(error)})
            return
        self.send_json(200, {**incident.model_dump(mode="json"), "changed_by": changed_by})

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), format % args)


def poll_loop() -> None:
    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            poll_siem()
        except Exception:
            logger.exception("El sondeo periodico fallo")


def warn_authentication_disabled() -> None:
    global _auth_warning_emitted
    with _auth_warning_lock:
        if _auth_warning_emitted:
            return
        logger.warning("AUTH_URL no configurada: endpoints del SOAR sin autenticación")
        _auth_warning_emitted = True


def main() -> None:
    if not identity_url_from_env():
        warn_authentication_disabled()
    connect_database().close()
    if POLL_INTERVAL_SECONDS > 0:
        threading.Thread(target=poll_loop, daemon=True, name="siem-poller").start()
    server = ThreadingHTTPServer(("0.0.0.0", 80), SoarHandler)
    logger.info("SOAR escuchando en el puerto 80")
    server.serve_forever()


if __name__ == "__main__":
    main()
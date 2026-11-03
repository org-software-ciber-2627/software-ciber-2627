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

from soar.services.pipeline import IncidentNotFoundError, SoarPipeline
from soar.services.status_service import (
    IncidentClosedError,
    InvalidTransitionError,
    MissingJustificationError,
    MissingResolutionReasonError,
)


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soar")

DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/soar.db")
SIEM_URL = os.getenv("SIEM_URL") or os.getenv("SIEM_API_URL") or "http://siem:80"
SIEM_URL = SIEM_URL.rstrip("/").removesuffix("/alerts")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", os.getenv("SOAR_POLLING_INTERVAL", "0")))


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


# Campos añadidos en el Sprint 2; las filas anteriores sin Incident normalizado los devuelven vacíos
EMPTY_INCIDENT_VIEW = {"incident_id": None, "priority": None, "status": None, "automation": None, "responses": []}


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
            "alert": json.loads(row["alert_json"]),
            "first_seen": row["first_seen"],
            **views.get(row["alert_key"], EMPTY_INCIDENT_VIEW),
        }
        for row in rows
    ]


def fetch_alerts() -> list[dict[str, Any]]:
    request = urllib.request.Request(f"{SIEM_URL}/alerts", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
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
STATUS_PATH = re.compile(r"^/incidents/([^/]+)/status$")
STATUS_ERRORS = (
    IncidentClosedError,
    InvalidTransitionError,
    MissingJustificationError,
    MissingResolutionReasonError,
    ValueError,
)


class SoarHandler(BaseHTTPRequestHandler):
    def send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        try:
            self.handle_get(urlparse(self.path).path)
        except Exception:
            logger.exception("Error no previsto en GET %s", self.path)
            self.send_json(500, {"error": "internal_error"})

    def do_POST(self) -> None:
        try:
            self.handle_post(urlparse(self.path).path)
        except Exception:
            logger.exception("Error no previsto en POST %s", self.path)
            self.send_json(500, {"error": "internal_error"})

    def handle_get(self, path: str) -> None:
        responses_match = RESPONSES_PATH.match(path)
        if path == "/health":
            self.send_json(200, {"status": "ok", "module": "06-soar"})
        elif path == "/incidents":
            self.send_json(200, list_incidents())
        elif responses_match:
            try:
                responses = build_pipeline().list_responses(responses_match.group(1))
            except IncidentNotFoundError:
                self.send_json(404, {"error": "incident_not_found"})
                return
            self.send_json(200, [response.model_dump(mode="json") for response in responses])
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
        try:
            incident = build_pipeline().change_status(
                incident_id,
                body["status"],
                body.get("justification") or "",
                body.get("resolution_reason"),
            )
        except IncidentNotFoundError:
            self.send_json(404, {"error": "incident_not_found"})
            return
        except STATUS_ERRORS as error:
            self.send_json(400, {"error": str(error)})
            return
        self.send_json(200, incident.model_dump(mode="json"))

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), format % args)


def poll_loop() -> None:
    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            poll_siem()
        except Exception:
            logger.exception("El sondeo periodico fallo")


def main() -> None:
    connect_database().close()
    if POLL_INTERVAL_SECONDS > 0:
        threading.Thread(target=poll_loop, daemon=True, name="siem-poller").start()
    server = ThreadingHTTPServer(("0.0.0.0", 80), SoarHandler)
    logger.info("SOAR escuchando en el puerto 80")
    server.serve_forever()


if __name__ == "__main__":
    main()

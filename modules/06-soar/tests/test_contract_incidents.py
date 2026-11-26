from __future__ import annotations

import json
import threading
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import app as soar_app
from soar.services.playbook_service import PlaybookService


EXPECTED_INCIDENT_KEYS = {
    "id",
    "alert_key",
    "alert",
    "first_seen",
    "incident_id",
    "alert_id",
    "event_type",
    "severity",
    "priority",
    "source_ip",
    "status",
    "created_at",
    "resolved_at",
    "applied_playbook",
    "automation",
    "responses",
}

ALLOWED_STATUSES = {"open", "in_progress", "contained", "closed"}


def _assert_iso_utc(value: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 0


def _start_contract_server(db_path: Path, monkeypatch) -> tuple[ThreadingHTTPServer, str]:
    monkeypatch.setattr(soar_app, "DATABASE_PATH", str(db_path))
    soar_app.connect_database().close()
    server = ThreadingHTTPServer(("127.0.0.1", 0), soar_app.SoarHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def test_contract_get_incidents_empty_list(tmp_path: Path, monkeypatch) -> None:
    server, base_url = _start_contract_server(tmp_path / "contract_empty.db", monkeypatch)
    try:
        with urllib.request.urlopen(f"{base_url}/incidents") as response:
            assert response.status == 200
            assert response.headers.get("Content-Type") == "application/json"
            payload = json.loads(response.read().decode("utf-8"))

        assert payload == []
    finally:
        server.shutdown()
        server.server_close()


def test_contract_get_incidents_schema_types_and_privacy(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "contract_full.db"
    server, base_url = _start_contract_server(db_path, monkeypatch)
    try:
        playbooks = PlaybookService(notify_url="", http_post=lambda *args: 200)
        pipeline = soar_app.SoarPipeline(
            str(db_path),
            register_alert=soar_app.save_alert,
            alert_key=soar_app.alert_key,
            playbook_service=playbooks,
        )
        outcome = pipeline.process_alert(
            {
                "alert_id": "AL-CONTRACT-001",
                "event_id": "EVT-CONTRACT-001",
                "event_type": "brute_force",
                "severity": "high",
                "source": "honeypot",
                "source_ip": "192.0.2.55",
                "timestamp": "2026-11-26T10:00:00+00:00",
                "title": "Intento de fuerza bruta SSH",
                "description": "Multiples intentos fallidos de autenticacion",
                "details": {
                    "service": "ssh",
                    "username": "usuario_anidado",
                },
                "username": "usuario_contrato",
                "credential": "secreto_contrato",
            }
        )
        assert outcome["result"] == "created"

        with urllib.request.urlopen(f"{base_url}/incidents") as response:
            assert response.status == 200
            raw_body = response.read().decode("utf-8")
            payload = json.loads(raw_body)

        assert isinstance(payload, list)
        assert len(payload) == 1
        item = payload[0]

        # 1. Exactamente las 16 claves congeladas con Grupo 7
        assert set(item.keys()) == EXPECTED_INCIDENT_KEYS

        # 2. Tipos y formatos obligatorios
        assert isinstance(item["id"], int)
        assert isinstance(item["alert_key"], str)
        assert isinstance(item["alert"], dict)
        assert isinstance(item["first_seen"], str)
        _assert_iso_utc(item["first_seen"])

        assert isinstance(item["incident_id"], str)
        assert item["status"] in ALLOWED_STATUSES
        assert isinstance(item["created_at"], str)
        _assert_iso_utc(item["created_at"])
        assert item["resolved_at"] is None
        assert isinstance(item["responses"], list)

        # 3. Privacidad: datos sensibles enmascarados (primer nivel y anidados)
        assert item["alert"]["username"] == "***"
        assert item["alert"]["credential"] == "***"
        assert item["alert"]["details"]["username"] == "***"
        assert "secreto_contrato" not in raw_body
        assert "usuario_contrato" not in raw_body
        assert "usuario_anidado" not in raw_body
    finally:
        server.shutdown()
        server.server_close()
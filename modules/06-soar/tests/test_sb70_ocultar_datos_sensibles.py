from __future__ import annotations

import json
import sqlite3
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import app as soar_app


def _start_test_server(db_path: Path, monkeypatch) -> tuple[ThreadingHTTPServer, str]:
    monkeypatch.setattr(soar_app, "DATABASE_PATH", str(db_path))
    soar_app.connect_database().close()
    server = ThreadingHTTPServer(("127.0.0.1", 0), soar_app.SoarHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def test_get_incidents_masks_credential_and_username(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "test_sb70.db"
    server, base_url = _start_test_server(db_path, monkeypatch)
    try:
        soar_app.save_alert(
            {
                "alert_id": "AL-SB70-1",
                "source_ip": "10.0.0.5",
                "event_type": "brute_force",
                "username": "usuario_ficticio",
                "credential": "clave_ficticia_123",
                "details": {
                    "username": "sub_usuario_ficticio",
                    "credential": "sub_clave_ficticia",
                },
            }
        )

        with urllib.request.urlopen(f"{base_url}/incidents") as response:
            assert response.status == 200
            raw_body = response.read().decode("utf-8")
            payload = json.loads(raw_body)

        assert len(payload) == 1
        alert = payload[0]["alert"]
        assert alert["source_ip"] == "10.0.0.5"
        assert alert["username"] == "***"
        assert alert["credential"] == "***"
        assert alert["details"]["username"] == "***"
        assert alert["details"]["credential"] == "***"
        assert "clave_ficticia_123" not in raw_body
        assert "sub_clave_ficticia" not in raw_body

        # Comprobamos que en SQLite interno no se destruyó la alerta original
        conn = sqlite3.connect(str(db_path))
        stored_json = conn.execute("SELECT alert_json FROM incidents").fetchone()[0]
        conn.close()
        assert "usuario_ficticio" in stored_json
    finally:
        server.shutdown()
        server.server_close()


def test_get_incidents_without_sensitive_fields(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "test_sb70_clean.db"
    server, base_url = _start_test_server(db_path, monkeypatch)
    try:
        soar_app.save_alert(
            {
                "alert_id": "AL-SB70-2",
                "source_ip": "10.0.0.9",
                "event_type": "port_scan",
            }
        )

        with urllib.request.urlopen(f"{base_url}/incidents") as response:
            assert response.status == 200
            payload = json.loads(response.read().decode("utf-8"))

        assert len(payload) == 1
        assert payload[0]["alert"] == {
            "alert_id": "AL-SB70-2",
            "source_ip": "10.0.0.9",
            "event_type": "port_scan",
        }
    finally:
        server.shutdown()
        server.server_close()
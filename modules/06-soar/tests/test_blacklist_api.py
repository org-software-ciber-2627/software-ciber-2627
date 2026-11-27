"""HU19.4: GET /blacklist sobre el flujo real del SOAR (SQLite en tmp_path, sin red)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest

import app as soar_app
from soar.models.blacklist_entry import BlacklistEntry
from soar.repositories.blacklist_repository import SqliteBlacklistRepository
from soar.services.blacklist_service import BlacklistService

BLACKLIST_KEYS = {"ip", "incident_id", "added_at", "reason"}
MOCK_ALERTS = json.loads(
    (Path(__file__).resolve().parent.parent / "mocks" / "alertas_mock.json").read_text(encoding="utf-8")
)["alerts"]


def brute_force_alert(alert_id: str, source_ip: str) -> dict:
    alert = json.loads(json.dumps(MOCK_ALERTS[1]))
    alert["alert_id"] = alert_id
    alert["source_ip"] = source_ip
    alert["details"]["source_ip"] = source_ip
    return alert


@pytest.fixture(autouse=True)
def demo_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sin notify al grupo 7 ni redes excluidas extra, como en la demo
    monkeypatch.setenv("GROUP7_NOTIFY_URL", "")
    monkeypatch.setenv("BLACKLIST_EXCLUDED_NETWORKS", "")


@contextmanager
def serve(database_path: Path) -> Iterator[str]:
    with patch.object(soar_app, "DATABASE_PATH", str(database_path)):
        server = ThreadingHTTPServer(("127.0.0.1", 0), soar_app.SoarHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def poll(database_path: Path, *alerts: dict) -> None:
    with patch.object(soar_app, "DATABASE_PATH", str(database_path)), patch.object(
        soar_app, "fetch_alerts", return_value=list(alerts)
    ):
        soar_app.poll_siem()


def get_json(url: str) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def test_empty_blacklist_returns_an_empty_list(tmp_path: Path) -> None:
    with serve(tmp_path / "soar.db") as base_url:
        status, payload = get_json(f"{base_url}/blacklist")

    assert (status, payload) == (200, [])


def test_two_brute_force_alerts_with_different_ips_are_listed_in_order(tmp_path: Path) -> None:
    database_path = tmp_path / "soar.db"
    poll(database_path, brute_force_alert("SIEM-BL-1", "203.0.113.7"), brute_force_alert("SIEM-BL-2", "198.51.100.9"))

    with serve(database_path) as base_url:
        status, payload = get_json(f"{base_url}/blacklist")
        _, incidents = get_json(f"{base_url}/incidents")

    assert status == 200
    assert [entry["ip"] for entry in payload] == ["203.0.113.7", "198.51.100.9"]
    incident_ids = {incident["alert_id"]: incident["incident_id"] for incident in incidents}
    assert [entry["incident_id"] for entry in payload] == [incident_ids["SIEM-BL-1"], incident_ids["SIEM-BL-2"]]
    for entry in payload:
        assert set(entry) == BLACKLIST_KEYS
        assert parse_utc(entry["added_at"]).utcoffset() == timedelta(0)
        assert entry["reason"] == "Incidente compatible con automatizacion"
    added = [parse_utc(entry["added_at"]) for entry in payload]
    assert added == sorted(added)


def test_entries_are_ordered_by_added_at_not_by_insertion(tmp_path: Path) -> None:
    database_path = tmp_path / "soar.db"
    repository = SqliteBlacklistRepository(str(database_path))
    base = datetime(2026, 11, 27, 10, 0, tzinfo=timezone.utc)
    repository.add(BlacklistEntry(ip="10.0.0.2", incident_id="INC-000002", added_at=base + timedelta(minutes=5), reason="b"))
    repository.add(BlacklistEntry(ip="10.0.0.1", incident_id="INC-000001", added_at=base, reason="a"))

    with serve(database_path) as base_url:
        status, payload = get_json(f"{base_url}/blacklist")

    assert status == 200
    assert [entry["ip"] for entry in payload] == ["10.0.0.1", "10.0.0.2"]
    assert payload[0]["added_at"] == "2026-11-27T10:00:00Z"


def test_the_same_ip_twice_appears_once(tmp_path: Path) -> None:
    database_path = tmp_path / "soar.db"
    poll(database_path, brute_force_alert("SIEM-BL-1", "203.0.113.7"), brute_force_alert("SIEM-BL-2", "203.0.113.7"))

    with serve(database_path) as base_url:
        status, payload = get_json(f"{base_url}/blacklist")
        _, incidents = get_json(f"{base_url}/incidents")

    assert status == 200
    assert len(incidents) == 2
    first_incident = next(i["incident_id"] for i in incidents if i["alert_id"] == "SIEM-BL-1")
    assert [(entry["ip"], entry["incident_id"]) for entry in payload] == [("203.0.113.7", first_incident)]


def test_excluded_ip_is_not_listed(tmp_path: Path) -> None:
    database_path = tmp_path / "soar.db"
    poll(database_path, brute_force_alert("SIEM-BL-LOCAL", "127.0.0.1"), brute_force_alert("SIEM-BL-1", "203.0.113.7"))

    with serve(database_path) as base_url:
        status, payload = get_json(f"{base_url}/blacklist")

    assert status == 200
    assert [entry["ip"] for entry in payload] == ["203.0.113.7"]


def test_internal_error_returns_500(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with serve(tmp_path / "soar.db") as base_url, patch.object(
        BlacklistService, "list_blacklist", side_effect=RuntimeError("database is locked")
    ), caplog.at_level("ERROR", logger="soar"):
        status, payload = get_json(f"{base_url}/blacklist")

    assert (status, payload) == (500, {"error": "internal_error"})
    assert "Error no previsto en GET /blacklist" in caplog.text

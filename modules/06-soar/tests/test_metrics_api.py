from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import app as soar_app
from soar.models.incident import Incident
from soar.repositories.incident_repository import SqliteIncidentRepository


@contextmanager
def _serve_database(database_path: Path) -> Iterator[str]:
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


def _incident(
    incident_id: str,
    *,
    status: str = "open",
    alert_timestamp: str | None = None,
    created_at: str = "2026-11-26T00:00:00+00:00",
) -> Incident:
    return Incident(
        incident_id=incident_id,
        alert_id=f"ALERT-{incident_id}",
        event_type="brute_force",
        severity="high",
        status=status,
        created_at=created_at,
        alert_timestamp=alert_timestamp,
    )


def _get_json(url: str) -> tuple[int, dict[str, object]]:
    with urllib.request.urlopen(url) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_get_metrics_returns_nulls_and_zero_counts_for_empty_database(tmp_path: Path) -> None:
    with _serve_database(tmp_path / "metrics_empty.db") as base_url:
        status, payload = _get_json(f"{base_url}/metrics")

    assert status == 200
    assert payload == {
        "mttd_seconds": None,
        "mttr_seconds": None,
        "total_incidents": 0,
        "closed_incidents": 0,
    }
    assert payload["mttd_seconds"] is None
    assert payload["mttr_seconds"] is None
    assert set(payload) == {
        "mttd_seconds",
        "mttr_seconds",
        "total_incidents",
        "closed_incidents",
    }


def test_get_metrics_for_open_incidents_keeps_missing_values_null(tmp_path: Path) -> None:
    database_path = tmp_path / "metrics_open.db"
    with _serve_database(database_path) as base_url:
        SqliteIncidentRepository(str(database_path)).save(_incident("INC-OPEN"))

        status, payload = _get_json(f"{base_url}/metrics")

    assert status == 200
    assert payload["total_incidents"] >= 1
    assert payload["closed_incidents"] == 0
    assert payload["mttd_seconds"] is None
    assert payload["mttr_seconds"] is None


def test_get_metrics_calculates_mttd_in_seconds(tmp_path: Path) -> None:
    database_path = tmp_path / "metrics_mttd.db"
    incident = _incident(
        "INC-MTTD",
        alert_timestamp="2026-11-25T23:59:58+00:00",
    )
    with _serve_database(database_path) as base_url:
        SqliteIncidentRepository(str(database_path)).save(incident)

        status, payload = _get_json(f"{base_url}/metrics")

    assert status == 200
    assert payload["mttd_seconds"] == 2.0
    assert payload["mttr_seconds"] is None


def test_closing_incident_over_http_calculates_deterministic_mttr(tmp_path: Path) -> None:
    database_path = tmp_path / "metrics_closed.db"
    incident = _incident("INC-CLOSED")
    fixed_now = datetime(2026, 11, 26, 0, 2, tzinfo=timezone.utc)
    with _serve_database(database_path) as base_url:
        SqliteIncidentRepository(str(database_path)).save(incident)
        with patch.object(
            soar_app,
            "build_pipeline",
            side_effect=lambda: soar_app.SoarPipeline(
                str(database_path),
                register_alert=soar_app.save_alert,
                alert_key=soar_app.alert_key,
                clock=lambda: fixed_now,
            ),
        ):
            request = urllib.request.Request(
                f"{base_url}/incidents/{incident.incident_id}/status",
                data=json.dumps(
                    {
                        "status": "closed",
                        "justification": "Incidente resuelto",
                        "resolution_reason": "Actividad bloqueada",
                        "changed_by": "analista",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                assert response.status == 200

        status, payload = _get_json(f"{base_url}/metrics")

    assert status == 200
    assert payload["closed_incidents"] == 1
    assert payload["mttr_seconds"] == 120.0
    assert payload["mttd_seconds"] is None


def test_get_metrics_internal_error_returns_500_and_server_stays_available(
    tmp_path: Path,
) -> None:
    with _serve_database(tmp_path / "metrics_error.db") as base_url:
        with patch.object(
            soar_app.MetricsService,
            "calculate_metrics",
            side_effect=RuntimeError("test internal error"),
        ):
            try:
                urllib.request.urlopen(f"{base_url}/metrics")
            except urllib.error.HTTPError as error:
                assert error.code == 500
                payload = json.loads(error.read().decode("utf-8"))
            else:
                raise AssertionError("GET /metrics debe devolver 500")

        status, health = _get_json(f"{base_url}/health")

    assert payload == {"error": "internal_error"}
    assert status == 200
    assert health == {"status": "ok", "module": "06-soar"}

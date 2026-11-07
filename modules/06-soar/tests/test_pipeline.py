import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app
from soar.repositories.incident_repository import SqliteIncidentRepository
from soar.services.playbook_service import PlaybookService


MOCK_ALERTS = json.loads(
    (Path(__file__).resolve().parent.parent / "mocks" / "alertas_mock.json").read_text(encoding="utf-8")
)["alerts"]
PORT_SCAN_ALERT, BRUTE_FORCE_ALERT = MOCK_ALERTS[0], MOCK_ALERTS[1]

# Campos del primer nivel que salen del Incident normalizado
FLAT_FIELDS = (
    "incident_id", "alert_id", "event_type", "severity", "priority",
    "source_ip", "status", "created_at", "resolved_at",
)
INCIDENT_FIELDS = ("id", "alert_key", "alert", "first_seen") + FLAT_FIELDS + ("applied_playbook", "automation", "responses")


class FakeHttpPost:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.calls = []

    def __call__(self, url, payload, timeout):
        self.calls.append(payload)
        return self.status_code


class PipelineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.directory.name, "soar.db")
        self.http_post = FakeHttpPost()
        patcher = patch.object(app, "DATABASE_PATH", self.database_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.directory.cleanup)

    def build_pipeline(self, notify_url="http://dashboard/notifications"):
        playbooks = PlaybookService(notify_url=notify_url, http_post=self.http_post)
        return app.SoarPipeline(
            self.database_path, register_alert=app.save_alert, alert_key=app.alert_key, playbook_service=playbooks
        )

    def find_incident(self, alert_id):
        return next(item for item in app.list_incidents() if item["alert"]["alert_id"] == alert_id)


class TestPipeline(PipelineTestCase):
    def test_brute_force_alert_runs_the_full_flow(self):
        outcome = self.build_pipeline().process_alert(BRUTE_FORCE_ALERT)

        self.assertEqual(outcome, {"result": "created", "automated": True})
        incident = self.find_incident("SIEM-ALERT-EJEMPLO-002")
        self.assertRegex(incident["incident_id"], r"^INC-[0-9A-F]{6}$")
        self.assertEqual(incident["priority"], "medium")
        self.assertEqual(incident["status"], "in_progress")
        self.assertEqual(incident["automation"]["automatable"], True)
        self.assertEqual(incident["automation"]["playbook"], "brute_force")
        self.assertEqual(len(incident["responses"]), 1)
        self.assertEqual(incident["responses"][0]["action"], "notify")
        self.assertEqual(incident["responses"][0]["status"], "success")
        self.assertEqual(self.http_post.calls[0]["incident_id"], incident["incident_id"])

    def test_status_change_is_recorded_in_history(self):
        pipeline = self.build_pipeline()
        pipeline.process_alert(BRUTE_FORCE_ALERT)
        incident_id = self.find_incident("SIEM-ALERT-EJEMPLO-002")["incident_id"]

        history = pipeline._status.get_history(incident_id)

        self.assertEqual([(c.from_status.value, c.to_status.value) for c in history], [("open", "in_progress")])
        self.assertEqual(history[0].justification, "Respuesta automática ejecutada: notify")

    def test_repeated_alert_creates_nothing_and_does_not_rerun_playbook(self):
        self.build_pipeline().process_alert(BRUTE_FORCE_ALERT)

        outcome = self.build_pipeline().process_alert(dict(BRUTE_FORCE_ALERT))

        self.assertEqual(outcome, {"result": "ignored", "automated": False})
        self.assertEqual(len(app.list_incidents()), 1)
        self.assertEqual(len(self.http_post.calls), 1)
        self.assertEqual(len(self.find_incident("SIEM-ALERT-EJEMPLO-002")["responses"]), 1)

    def test_port_scan_is_stored_but_not_automated(self):
        outcome = self.build_pipeline().process_alert(PORT_SCAN_ALERT)

        self.assertEqual(outcome, {"result": "created", "automated": False})
        incident = self.find_incident("SIEM-ALERT-EJEMPLO-001")
        self.assertEqual(incident["status"], "open")
        self.assertFalse(incident["automation"]["automatable"])
        self.assertEqual(incident["responses"], [])
        self.assertEqual(self.http_post.calls, [])

    def test_skipped_notify_is_recorded_and_incident_stays_open(self):
        outcome = self.build_pipeline(notify_url="").process_alert(BRUTE_FORCE_ALERT)

        self.assertEqual(outcome, {"result": "created", "automated": True})
        incident = self.find_incident("SIEM-ALERT-EJEMPLO-002")
        self.assertEqual(incident["status"], "open")
        self.assertEqual(incident["responses"][0]["status"], "skipped")

    def test_applied_playbook_with_skipped_response_is_brute_force(self):
        self.build_pipeline(notify_url="").process_alert(BRUTE_FORCE_ALERT)

        incident = self.find_incident("SIEM-ALERT-EJEMPLO-002")

        self.assertEqual(incident["responses"][0]["status"], "skipped")
        self.assertEqual(incident["applied_playbook"], "brute_force")

    def test_applied_playbook_without_responses_is_null(self):
        self.build_pipeline().process_alert(PORT_SCAN_ALERT)

        incident = self.find_incident("SIEM-ALERT-EJEMPLO-001")

        self.assertEqual(incident["responses"], [])
        self.assertIsNone(incident["applied_playbook"])

    def test_flat_fields_match_the_normalized_incident(self):
        self.build_pipeline().process_alert(BRUTE_FORCE_ALERT)

        view = self.find_incident("SIEM-ALERT-EJEMPLO-002")
        incident = SqliteIncidentRepository(self.database_path).find_by_alert_key("SIEM-ALERT-EJEMPLO-002")

        for field in FLAT_FIELDS:
            self.assertEqual(view[field], getattr(incident, field), field)
        self.assertEqual(datetime.fromisoformat(view["created_at"]).utcoffset().total_seconds(), 0)

    def test_old_fields_are_kept_and_legacy_rows_return_null(self):
        self.build_pipeline().process_alert(BRUTE_FORCE_ALERT)
        app.save_alert({"alert_id": "SIEM-SPRINT-1"})

        new_row = self.find_incident("SIEM-ALERT-EJEMPLO-002")
        legacy_row = self.find_incident("SIEM-SPRINT-1")

        self.assertEqual(new_row["alert"], BRUTE_FORCE_ALERT)
        self.assertEqual(new_row["alert_key"], "SIEM-ALERT-EJEMPLO-002")
        self.assertIsInstance(new_row["id"], int)
        self.assertIsNotNone(new_row["first_seen"])
        self.assertEqual(set(new_row), set(legacy_row))
        for field in FLAT_FIELDS + ("applied_playbook", "automation"):
            self.assertIsNone(legacy_row[field], field)
        self.assertEqual(legacy_row["responses"], [])

    def test_invalid_alert_is_rejected_and_not_stored(self):
        with self.assertLogs("soar", level="WARNING"):
            outcome = self.build_pipeline().process_alert({"alert_id": "SIEM-MALA", "source": "firewall"})

        self.assertEqual(outcome, {"result": "rejected", "automated": False})
        self.assertEqual(app.list_incidents(), [])

    def test_poll_siem_counts_every_outcome(self):
        alerts = [PORT_SCAN_ALERT, BRUTE_FORCE_ALERT, BRUTE_FORCE_ALERT, {"alert_id": "SIEM-MALA"}]
        with patch.object(app, "fetch_alerts", return_value=alerts), patch.object(
            app, "build_pipeline", side_effect=lambda: self.build_pipeline()
        ):
            result = app.poll_siem()

        self.assertEqual(result, {"received": 4, "created": 2, "ignored": 1, "rejected": 1, "automated": 1})


class TestHttpApi(PipelineTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.build_pipeline().process_alert(BRUTE_FORCE_ALERT)
        self.incident_id = self.find_incident("SIEM-ALERT-EJEMPLO-002")["incident_id"]
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.SoarHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        url = f"http://127.0.0.1:{self.server.server_port}{path}"
        request = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_get_incidents_keeps_old_fields_and_adds_new_ones(self):
        status, body = self.request("GET", "/incidents")

        self.assertEqual(status, 200)
        self.assertEqual(set(body[0]), set(INCIDENT_FIELDS))

    def test_get_responses(self):
        status, body = self.request("GET", f"/incidents/{self.incident_id}/responses")

        self.assertEqual(status, 200)
        self.assertEqual([r["action"] for r in body], ["notify"])

    def test_get_responses_of_unknown_incident_returns_404(self):
        self.assertEqual(self.request("GET", "/incidents/INC-NOPE/responses")[0], 404)

    def test_change_status(self):
        status, body = self.request(
            "POST", f"/incidents/{self.incident_id}/status",
            {"status": "closed", "justification": "Revisado", "resolution_reason": "IP bloqueada a mano"},
        )

        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "closed")
        self.assertIsNotNone(body["resolved_at"])

    def test_invalid_transition_returns_400(self):
        status, body = self.request(
            "POST", f"/incidents/{self.incident_id}/status", {"status": "open", "justification": "Volver"}
        )

        self.assertEqual(status, 400)
        self.assertIn("not allowed", body["error"])

    def test_change_status_of_unknown_incident_returns_404(self):
        status, _ = self.request("POST", "/incidents/INC-NOPE/status", {"status": "closed", "justification": "x"})

        self.assertEqual(status, 404)

    def test_unexpected_error_returns_500(self):
        with patch.object(app, "list_incidents", side_effect=Exception("boom")), self.assertLogs("soar", "ERROR"):
            status, body = self.request("GET", "/incidents")

        self.assertEqual((status, body), (500, {"error": "internal_error"}))


if __name__ == "__main__":
    unittest.main()

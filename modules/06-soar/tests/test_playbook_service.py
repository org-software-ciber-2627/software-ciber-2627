import unittest
import urllib.error
from datetime import datetime, timezone

from pydantic import ValidationError

from soar.models.incident import Incident
from soar.models.playbook import ActionResult, BruteForcePlaybookInput, BruteForcePlaybookOutput, playbook_status
from soar.services.playbook_service import NOTIFY_TIMEOUT_SECONDS, PlaybookService


FIXED_TIME = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
NOTIFY_URL = "http://dashboard/notifications"


def create_incident(**overrides):
    data = {
        "incident_id": "INC-001",
        "alert_id": "SIEM-ALERT-EJEMPLO-002",
        "event_type": "fuerza_bruta",
        "severity": "high",
        "priority": "high",
        "source_ip": "192.168.1.50",
        "status": "open",
        "created_at": "2026-11-03T11:59:00+00:00",
        "details": {"service": "ssh", "username": "root", "failed_attempts": 7},
    }
    data.update(overrides)
    return Incident(**data)


def action(status):
    return ActionResult(action_name="notify", target="group7", status=status, details="d")


class FakeHttpPost:
    def __init__(self, status_code=200, error=None):
        self.status_code = status_code
        self.error = error
        self.calls = []

    def __call__(self, url, payload, timeout):
        self.calls.append((url, payload, timeout))
        if self.error:
            raise self.error
        return self.status_code


class TestPlaybookInput(unittest.TestCase):
    def test_from_incident_maps_incident_fields(self):
        playbook_input = BruteForcePlaybookInput.from_incident(create_incident())

        self.assertEqual(playbook_input.incident_id, "INC-001")
        self.assertEqual(playbook_input.source_ip, "192.168.1.50")
        self.assertEqual(playbook_input.service, "ssh")
        self.assertEqual(playbook_input.username, "root")
        self.assertEqual(playbook_input.usernames, ["root"])
        self.assertEqual(playbook_input.failed_attempts, 7)

    def test_from_incident_maps_ids_fields(self):
        incident = create_incident(
            event_type="brute_force",
            source="ids",
            details={"service": "sshd", "attempts": 12, "usernames": ["root", "admin"]},
        )

        playbook_input = BruteForcePlaybookInput.from_incident(incident)

        self.assertEqual(playbook_input.failed_attempts, 12)
        self.assertEqual(playbook_input.usernames, ["root", "admin"])
        self.assertEqual(playbook_input.username, "root")

    def test_incident_that_is_not_brute_force_is_rejected(self):
        with self.assertRaises(ValueError):
            BruteForcePlaybookInput.from_incident(create_incident(event_type="port_scan"))

    def test_from_incident_does_not_modify_incident(self):
        incident = create_incident()
        snapshot = incident.model_dump()

        BruteForcePlaybookInput.from_incident(incident)

        self.assertEqual(incident.model_dump(), snapshot)


class TestPlaybookService(unittest.TestCase):
    def execute(self, http_post, notify_url=NOTIFY_URL):
        service = PlaybookService(notify_url=notify_url, http_post=http_post, clock=lambda: FIXED_TIME)
        playbook_input = BruteForcePlaybookInput.from_incident(create_incident())
        return service.execute_brute_force_playbook(playbook_input, reason="Incidente compatible con automatizacion")

    def test_notify_success(self):
        http_post = FakeHttpPost(status_code=201)

        output = self.execute(http_post)

        self.assertEqual(output.status, "COMPLETED")
        self.assertEqual(output.playbook, "brute_force")
        self.assertEqual([a.action_name for a in output.actions_taken], ["notify"])
        self.assertEqual(output.actions_taken[0].status, "success")
        url, payload, timeout = http_post.calls[0]
        self.assertEqual(url, NOTIFY_URL)
        self.assertEqual(timeout, NOTIFY_TIMEOUT_SECONDS)
        self.assertEqual(payload, {
            "incident_id": "INC-001",
            "event_type": "fuerza_bruta",
            "severity": "high",
            "priority": "high",
            "source_ip": "192.168.1.50",
            "service": "ssh",
            "username": "root",
            "usernames": ["root"],
            "failed_attempts": 7,
            "playbook": "brute_force",
            "reason": "Incidente compatible con automatizacion",
            "detected_at": "2026-11-03T11:59:00+00:00",
        })

    def test_notify_includes_ids_attempts_and_usernames(self):
        http_post = FakeHttpPost(status_code=200)
        incident = create_incident(
            event_type="brute_force",
            source="ids",
            details={"service": "sshd", "attempts": 12, "usernames": ["root", "admin"]},
        )
        playbook_input = BruteForcePlaybookInput.from_incident(incident)

        PlaybookService(
            notify_url=NOTIFY_URL, http_post=http_post, clock=lambda: FIXED_TIME
        ).execute_brute_force_playbook(playbook_input)

        self.assertEqual(http_post.calls[0][1]["failed_attempts"], 12)
        self.assertEqual(http_post.calls[0][1]["usernames"], ["root", "admin"])
        self.assertEqual(http_post.calls[0][1]["username"], "root")

    def test_notify_with_http_error_fails(self):
        error = urllib.error.HTTPError(NOTIFY_URL, 503, "Service Unavailable", {}, None)

        output = self.execute(FakeHttpPost(error=error))

        self.assertEqual(output.status, "FAILED")
        self.assertEqual(output.actions_taken[0].status, "failed")
        self.assertIn("503", output.actions_taken[0].details)

    def test_notify_with_status_code_400_or_more_fails(self):
        output = self.execute(FakeHttpPost(status_code=404))

        self.assertEqual(output.actions_taken[0].status, "failed")

    def test_notify_with_timeout_fails(self):
        output = self.execute(FakeHttpPost(error=TimeoutError("timed out")))

        self.assertEqual(output.status, "FAILED")
        self.assertEqual(output.actions_taken[0].status, "failed")
        self.assertIn("timed out", output.actions_taken[0].details)

    def test_notify_with_network_error_fails(self):
        output = self.execute(FakeHttpPost(error=urllib.error.URLError("connection refused")))

        self.assertEqual(output.actions_taken[0].status, "failed")

    def test_notify_without_url_is_skipped(self):
        http_post = FakeHttpPost()

        output = self.execute(http_post, notify_url="")

        self.assertEqual(output.status, "FAILED")
        self.assertEqual(output.actions_taken[0].status, "skipped")
        self.assertIn("GROUP7_NOTIFY_URL", output.actions_taken[0].details)
        self.assertEqual(http_post.calls, [])

    def test_executed_at_has_utc_timezone(self):
        output = PlaybookService(notify_url="").execute_brute_force_playbook(
            BruteForcePlaybookInput.from_incident(create_incident())
        )

        self.assertEqual(output.executed_at.utcoffset().total_seconds(), 0)

    def test_execution_does_not_modify_incident(self):
        incident = create_incident()
        snapshot = incident.model_dump()
        service = PlaybookService(notify_url=NOTIFY_URL, http_post=FakeHttpPost())

        service.execute_brute_force_playbook(BruteForcePlaybookInput.from_incident(incident))

        self.assertEqual(incident.model_dump(), snapshot)


class TestPlaybookStatus(unittest.TestCase):
    def test_all_success_is_completed(self):
        self.assertEqual(playbook_status([action("success"), action("success")]), "COMPLETED")

    def test_no_success_is_failed(self):
        self.assertEqual(playbook_status([action("failed"), action("skipped")]), "FAILED")
        self.assertEqual(playbook_status([]), "FAILED")

    def test_mixed_is_partial(self):
        self.assertEqual(playbook_status([action("success"), action("failed")]), "PARTIAL")

    def test_invalid_statuses_are_rejected(self):
        with self.assertRaises(ValidationError):
            action("ok")
        with self.assertRaises(ValidationError):
            BruteForcePlaybookOutput(
                execution_id="E", incident_id="INC-001", status="DONE",
                actions_taken=[], executed_at=FIXED_TIME, summary="",
            )


if __name__ == "__main__":
    unittest.main()

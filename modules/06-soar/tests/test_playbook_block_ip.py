import os
import tempfile
import unittest
from datetime import datetime, timezone

from soar.models.incident import Incident
from soar.models.playbook import BruteForcePlaybookInput
from soar.repositories.blacklist_repository import BlacklistRepository, SqliteBlacklistRepository
from soar.services.blacklist_service import BlacklistService
from soar.services.playbook_service import PlaybookService
from soar.services.response_mapper import responses_from_playbook_output


FIXED_TIME = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
NOTIFY_URL = "http://dashboard/notifications"
REASON = "Incidente compatible con automatizacion"


class FakeHttpPost:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.calls = []

    def __call__(self, url, payload, timeout):
        self.calls.append(payload)
        return self.status_code


class FailingBlacklist:
    """Lista negra que falla, por ejemplo porque la base de datos no está disponible."""

    def block(self, ip, incident_id, reason):
        raise RuntimeError("database is locked")


def playbook_input(source_ip="192.168.1.50", incident_id="INC-001"):
    incident = Incident(
        incident_id=incident_id,
        alert_id="SIEM-ALERT-EJEMPLO-002",
        event_type="fuerza_bruta",
        severity="high",
        source_ip=source_ip,
        status="open",
        created_at="2026-11-26T11:59:00+00:00",
        details={"service": "ssh", "username": "root"},
    )
    return BruteForcePlaybookInput.from_incident(incident)


def build_blacklist(repository=None):
    return BlacklistService(
        repository if repository is not None else BlacklistRepository(),
        clock=lambda: FIXED_TIME,
        excluded_networks=[],
    )


class TestBlockIpAction(unittest.TestCase):
    def setUp(self):
        self.http_post = FakeHttpPost()

    def execute(self, blacklist_service=None, notify_url="", source_ip="192.168.1.50", incident_id="INC-001"):
        service = PlaybookService(
            notify_url=notify_url, http_post=self.http_post, clock=lambda: FIXED_TIME,
            blacklist_service=blacklist_service,
        )
        return service.execute_brute_force_playbook(playbook_input(source_ip, incident_id), reason=REASON)

    @staticmethod
    def block_ip_action(output):
        return next(action for action in output.actions_taken if action.action_name == "block_ip")

    def test_new_ip_is_blocked_and_stored_in_the_blacklist(self):
        repository = BlacklistRepository()

        output = self.execute(build_blacklist(repository))

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "success")
        self.assertEqual(action.target, "192.168.1.50")
        self.assertIn("bloqueada", action.details)
        entry = repository.get_by_ip("192.168.1.50")
        self.assertEqual(entry.incident_id, "INC-001")
        self.assertEqual(entry.reason, REASON)
        self.assertEqual(entry.added_at, FIXED_TIME)

    def test_same_ip_twice_is_success_with_already_blocked(self):
        repository = BlacklistRepository()
        blacklist = build_blacklist(repository)
        self.execute(blacklist, incident_id="INC-001")

        output = self.execute(blacklist, incident_id="INC-002")

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "success")
        self.assertIn("ya estaba bloqueada", action.details)
        self.assertIn("contenida", action.details)
        self.assertEqual(len(repository.list_all()), 1)
        self.assertEqual(repository.get_by_ip("192.168.1.50").incident_id, "INC-001")

    def test_loopback_ip_is_skipped_as_protected(self):
        repository = BlacklistRepository()

        output = self.execute(build_blacklist(repository), source_ip="127.0.0.1")

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "skipped")
        self.assertEqual(action.target, "127.0.0.1")
        self.assertIn("protegida", action.details)
        self.assertEqual(repository.list_all(), [])

    def test_invalid_ip_fails(self):
        repository = BlacklistRepository()

        output = self.execute(build_blacklist(repository), source_ip="no-es-una-ip")

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "failed")
        self.assertIn("no válida", action.details)
        self.assertEqual(repository.list_all(), [])

    def test_without_blacklist_service_block_ip_is_skipped(self):
        output = self.execute(blacklist_service=None)

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "skipped")
        self.assertEqual(action.details, "Lista negra no configurada")

    def test_blacklist_error_fails_block_ip_and_notify_still_runs(self):
        output = self.execute(FailingBlacklist(), notify_url=NOTIFY_URL)

        action = self.block_ip_action(output)
        self.assertEqual(action.status, "failed")
        self.assertIn("database is locked", action.details)
        self.assertEqual(len(self.http_post.calls), 1)
        self.assertEqual(output.actions_taken[1].action_name, "notify")
        self.assertEqual(output.actions_taken[1].status, "success")
        self.assertEqual(output.status, "PARTIAL")

    def test_block_ip_runs_before_notify(self):
        output = self.execute(build_blacklist())

        self.assertEqual([action.action_name for action in output.actions_taken], ["block_ip", "notify"])
        self.assertEqual(output.summary, "block_ip=success, notify=skipped")

    def test_sqlite_blacklist_keeps_the_blocked_ip(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database_path = os.path.join(directory.name, "soar.db")

        self.execute(build_blacklist(SqliteBlacklistRepository(database_path)))

        self.assertEqual(SqliteBlacklistRepository(database_path).get_by_ip("192.168.1.50").incident_id, "INC-001")

    def test_block_ip_becomes_an_executed_response(self):
        output = self.execute(build_blacklist())

        response = responses_from_playbook_output(output)[0]

        self.assertEqual(response.action, "block_ip")
        self.assertEqual(response.status, "success")
        self.assertEqual(response.message, "IP 192.168.1.50 bloqueada")
        self.assertIsNone(response.error)
        self.assertEqual(response.details["target"], "192.168.1.50")
        self.assertEqual(response.details["playbook_status"], "PARTIAL")


class TestPlaybookGlobalStatus(unittest.TestCase):
    def execute(self, blacklist_service, notify_url, status_code=200, source_ip="192.168.1.50"):
        service = PlaybookService(
            notify_url=notify_url, http_post=FakeHttpPost(status_code), clock=lambda: FIXED_TIME,
            blacklist_service=blacklist_service,
        )
        return service.execute_brute_force_playbook(playbook_input(source_ip), reason=REASON)

    def test_blocked_and_notify_skipped_is_partial(self):
        # Caso de la demo: lista negra conectada y GROUP7_NOTIFY_URL sin configurar
        self.assertEqual(self.execute(build_blacklist(), notify_url="").status, "PARTIAL")

    def test_blocked_and_notified_is_completed(self):
        self.assertEqual(self.execute(build_blacklist(), notify_url=NOTIFY_URL).status, "COMPLETED")

    def test_already_blocked_and_notified_is_completed(self):
        blacklist = build_blacklist()
        self.execute(blacklist, notify_url=NOTIFY_URL)

        self.assertEqual(self.execute(blacklist, notify_url=NOTIFY_URL).status, "COMPLETED")

    def test_blocked_and_notify_failed_is_partial(self):
        self.assertEqual(self.execute(build_blacklist(), notify_url=NOTIFY_URL, status_code=503).status, "PARTIAL")

    def test_excluded_ip_and_notify_skipped_is_failed(self):
        self.assertEqual(self.execute(build_blacklist(), notify_url="", source_ip="127.0.0.1").status, "FAILED")

    def test_without_blacklist_and_notify_skipped_is_failed(self):
        self.assertEqual(self.execute(None, notify_url="").status, "FAILED")

    def test_without_blacklist_and_notified_is_partial(self):
        self.assertEqual(self.execute(None, notify_url=NOTIFY_URL).status, "PARTIAL")

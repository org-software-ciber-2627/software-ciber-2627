import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from pydantic import ValidationError

from soar.models.blacklist_entry import BlacklistEntry
from soar.repositories.blacklist_repository import (
    BlacklistRepository,
    DuplicateIpError,
    SqliteBlacklistRepository,
)
from soar.services.blacklist_service import EXCLUDED_NETWORKS_ENV, BlacklistService


FIXED_TIME = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)


class SteppingClock:
    """Reloj que avanza un segundo en cada llamada."""

    def __init__(self, start: datetime = FIXED_TIME) -> None:
        self._next = start

    def __call__(self) -> datetime:
        value = self._next
        self._next += timedelta(seconds=1)
        return value


def build_service(repository=None, clock=None, excluded_networks=()):
    return BlacklistService(
        repository if repository is not None else BlacklistRepository(),
        clock=clock or (lambda: FIXED_TIME),
        excluded_networks=excluded_networks,
    )


class TestBlacklistEntryModel(unittest.TestCase):
    def test_added_at_without_timezone_is_rejected(self):
        with self.assertRaises(ValidationError):
            BlacklistEntry(ip="1.2.3.4", incident_id="INC-001", added_at=datetime(2026, 11, 24), reason="x")

    def test_added_at_is_converted_to_utc(self):
        madrid = timezone(timedelta(hours=1))
        entry = BlacklistEntry(
            ip="1.2.3.4", incident_id="INC-001", added_at=datetime(2026, 11, 24, 11, 0, tzinfo=madrid), reason="x"
        )

        self.assertEqual(entry.added_at, FIXED_TIME)
        self.assertEqual(entry.added_at.tzinfo, timezone.utc)


class TestBlacklistService(unittest.TestCase):
    def test_new_ip_is_blocked_with_ip_incident_utc_date_and_reason(self):
        repository = BlacklistRepository()
        service = build_service(repository)

        result = service.block("203.0.113.7", "INC-001", "Fuerza bruta SSH")

        self.assertEqual(result.outcome, "blocked")
        self.assertEqual(result.ip, "203.0.113.7")
        entry = repository.get_by_ip("203.0.113.7")
        self.assertEqual(result.entry, entry)
        self.assertEqual(entry.ip, "203.0.113.7")
        self.assertEqual(entry.incident_id, "INC-001")
        self.assertEqual(entry.added_at, FIXED_TIME)
        self.assertEqual(entry.added_at.tzinfo, timezone.utc)
        self.assertEqual(entry.reason, "Fuerza bruta SSH")

    def test_blocking_the_same_ip_twice_keeps_the_original_entry(self):
        repository = BlacklistRepository()
        service = build_service(repository, clock=SteppingClock())
        first = service.block("203.0.113.7", "INC-001", "Primer motivo")

        second = service.block("203.0.113.7", "INC-002", "Segundo motivo")

        self.assertEqual(second.outcome, "already_blocked")
        self.assertEqual(second.entry, first.entry)
        self.assertEqual(len(repository.list_all()), 1)
        original = repository.get_by_ip("203.0.113.7")
        self.assertEqual(original.incident_id, "INC-001")
        self.assertEqual(original.reason, "Primer motivo")
        self.assertEqual(original.added_at, FIXED_TIME)

    def test_same_ip_written_differently_is_already_blocked(self):
        repository = BlacklistRepository()
        service = build_service(repository)
        service.block("2001:db8::1", "INC-001", "x")

        result = service.block(" 2001:0db8:0000::0001 ", "INC-002", "y")

        self.assertEqual(result.outcome, "already_blocked")
        self.assertEqual(len(repository.list_all()), 1)

    def test_invalid_ips_are_not_stored(self):
        repository = BlacklistRepository()
        service = build_service(repository)

        for ip in ("", "   ", None, "999.1.1.1", "192.168.1", "no-es-una-ip", "192.168.1.0/24", 12345):
            with self.subTest(ip=ip):
                result = service.block(ip, "INC-001", "x")
                self.assertEqual(result.outcome, "invalid_ip")
                self.assertIsNone(result.entry)
        self.assertEqual(repository.list_all(), [])

    def test_loopback_and_unspecified_ips_are_excluded(self):
        repository = BlacklistRepository()
        service = build_service(repository)

        for ip in ("127.0.0.1", "127.10.20.30", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1"):
            with self.subTest(ip=ip):
                result = service.block(ip, "INC-001", "x")
                self.assertEqual(result.outcome, "excluded")
                self.assertIsNone(result.entry)
        self.assertEqual(repository.list_all(), [])

    def test_ip_inside_configured_network_is_excluded(self):
        repository = BlacklistRepository()
        service = build_service(repository, excluded_networks=["172.28.0.0/16", "fd00::/8"])

        self.assertEqual(service.block("172.28.0.5", "INC-001", "x").outcome, "excluded")
        self.assertEqual(service.block("fd00::5", "INC-001", "x").outcome, "excluded")
        self.assertEqual(service.block("172.29.0.5", "INC-001", "x").outcome, "blocked")
        self.assertEqual([entry.ip for entry in repository.list_all()], ["172.29.0.5"])

    def test_excluded_networks_are_read_from_the_environment(self):
        with mock.patch.dict(os.environ, {EXCLUDED_NETWORKS_ENV: " 172.28.0.0/16 , ,10.0.0.0/8"}):
            service = BlacklistService(BlacklistRepository(), clock=lambda: FIXED_TIME)

        self.assertEqual(service.block("172.28.1.1", "INC-001", "x").outcome, "excluded")
        self.assertEqual(service.block("10.1.2.3", "INC-001", "x").outcome, "excluded")

    def test_badly_written_network_is_ignored_with_a_warning(self):
        with mock.patch.dict(os.environ, {EXCLUDED_NETWORKS_ENV: "no-es-red,172.28.0.0/16,300.0.0.0/8"}):
            with self.assertLogs("soar", level="WARNING") as logs:
                service = BlacklistService(BlacklistRepository(), clock=lambda: FIXED_TIME)

        self.assertEqual(len(logs.records), 2)
        self.assertEqual(service.block("172.28.0.5", "INC-001", "x").outcome, "excluded")
        self.assertEqual(service.block("203.0.113.7", "INC-001", "x").outcome, "blocked")

    def test_without_environment_variable_only_fixed_exclusions_apply(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            service = BlacklistService(BlacklistRepository(), clock=lambda: FIXED_TIME)

        self.assertEqual(service.block("172.28.0.5", "INC-001", "x").outcome, "blocked")

    def test_private_ips_can_be_blocked(self):
        service = build_service()

        for ip in ("192.168.1.50", "10.0.0.8"):
            with self.subTest(ip=ip):
                self.assertEqual(service.block(ip, "INC-001", "Demo").outcome, "blocked")

    def test_list_blacklist_is_ordered_by_date(self):
        later = BlacklistEntry(ip="10.0.0.2", incident_id="INC-002", added_at=FIXED_TIME + timedelta(minutes=5), reason="b")
        earlier = BlacklistEntry(ip="10.0.0.1", incident_id="INC-001", added_at=FIXED_TIME, reason="a")
        service = build_service(BlacklistRepository([later, earlier]))

        self.assertEqual([entry.ip for entry in service.list_blacklist()], ["10.0.0.1", "10.0.0.2"])

    def test_list_blacklist_is_empty_by_default(self):
        self.assertEqual(build_service().list_blacklist(), [])

    def test_race_on_add_is_reported_as_already_blocked(self):
        original = BlacklistEntry(ip="203.0.113.7", incident_id="INC-001", added_at=FIXED_TIME, reason="a")
        repository = BlacklistRepository()
        # Simula que otro proceso guarda la IP entre get_by_ip y add
        with mock.patch.object(repository, "get_by_ip", side_effect=[None, original]), \
                mock.patch.object(repository, "add", side_effect=DuplicateIpError("203.0.113.7")):
            result = build_service(repository).block("203.0.113.7", "INC-002", "b")

        self.assertEqual(result.outcome, "already_blocked")
        self.assertEqual(result.entry, original)


class TestBlacklistRepository(unittest.TestCase):
    def test_in_memory_repository_rejects_duplicates(self):
        repository = BlacklistRepository()
        repository.add(BlacklistEntry(ip="10.0.0.1", incident_id="INC-001", added_at=FIXED_TIME, reason="a"))

        with self.assertRaises(DuplicateIpError):
            repository.add(BlacklistEntry(ip="10.0.0.1", incident_id="INC-002", added_at=FIXED_TIME, reason="b"))
        self.assertEqual(repository.get_by_ip("10.0.0.1").incident_id, "INC-001")

    def test_get_by_unknown_ip_returns_none(self):
        self.assertIsNone(BlacklistRepository().get_by_ip("10.0.0.1"))


class TestSqliteBlacklistRepository(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database_path = os.path.join(directory.name, "soar.db")

    def test_entries_survive_recreating_the_repository(self):
        build_service(SqliteBlacklistRepository(self.database_path), clock=SteppingClock()).block(
            "192.168.1.50", "INC-001", "Fuerza bruta SSH"
        )

        service = build_service(SqliteBlacklistRepository(self.database_path))
        entries = service.list_blacklist()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].ip, "192.168.1.50")
        self.assertEqual(entries[0].incident_id, "INC-001")
        self.assertEqual(entries[0].reason, "Fuerza bruta SSH")
        self.assertEqual(entries[0].added_at, FIXED_TIME)
        self.assertEqual(service.block("192.168.1.50", "INC-002", "otro").outcome, "already_blocked")

    def test_repository_rejects_duplicates_and_keeps_the_original(self):
        repository = SqliteBlacklistRepository(self.database_path)
        repository.add(BlacklistEntry(ip="10.0.0.1", incident_id="INC-001", added_at=FIXED_TIME, reason="a"))

        with self.assertRaises(DuplicateIpError):
            repository.add(BlacklistEntry(ip="10.0.0.1", incident_id="INC-002", added_at=FIXED_TIME, reason="b"))

        self.assertEqual(len(repository.list_all()), 1)
        self.assertEqual(repository.get_by_ip("10.0.0.1").incident_id, "INC-001")

    def test_table_has_a_unique_constraint_on_ip(self):
        SqliteBlacklistRepository(self.database_path)
        connection = sqlite3.connect(self.database_path)
        self.addCleanup(connection.close)
        connection.execute("INSERT INTO ip_blacklist (ip, incident_id, entry_json) VALUES ('10.0.0.1', 'INC-001', '{}')")

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO ip_blacklist (ip, incident_id, entry_json) VALUES ('10.0.0.1', 'INC-002', '{}')")

    def test_list_all_keeps_insertion_order(self):
        service = build_service(SqliteBlacklistRepository(self.database_path), clock=SteppingClock())
        for ip in ("10.0.0.3", "10.0.0.1", "10.0.0.2"):
            service.block(ip, "INC-001", "x")

        self.assertEqual(
            [entry.ip for entry in SqliteBlacklistRepository(self.database_path).list_all()],
            ["10.0.0.3", "10.0.0.1", "10.0.0.2"],
        )
        self.assertEqual([entry.ip for entry in service.list_blacklist()], ["10.0.0.3", "10.0.0.1", "10.0.0.2"])

    def test_get_by_unknown_ip_returns_none(self):
        self.assertIsNone(SqliteBlacklistRepository(self.database_path).get_by_ip("10.0.0.1"))

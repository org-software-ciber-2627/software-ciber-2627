import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.append(str(Path(__file__).resolve().parents[1]))

from patterns.brute_force import BruteForce
from patterns.endpoint_scan import EndpointScan
from util.siem_publisher import (
    IdentityTokenProvider,
    publish_and_queue,
    publish_event,
    retry_pending,
    PUBLISH_SENT,
)


class FakeResponse:
    def __init__(self, status_code=200, event_id=None, token=None, text=""):
        self.status_code = status_code
        self.text = text
        self._event_id = event_id
        self._token = token

    def json(self):
        if self._token is not None:
            return {"token": self._token}
        if self._event_id is None:
            return {}
        return {"event_id": self._event_id}


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.request_calls = []

    def post(self, url, json, timeout, headers=None):
        self.request_calls.append({
            "url": url,
            "json": copy.deepcopy(json),
            "timeout": timeout,
            "headers": copy.deepcopy(headers),
        })
        if not url.endswith("/auth/login"):
            self.calls.append(copy.deepcopy(json))
        if not self.responses:
            raise RuntimeError("No fake response configured")
        return self.responses.pop(0)


class TimeoutSession:
    def __init__(self):
        self.calls = []
        self.request_calls = []

    def post(self, url, json, timeout, headers=None):
        self.calls.append(copy.deepcopy(json))
        self.request_calls.append({
            "url": url,
            "json": copy.deepcopy(json),
            "timeout": timeout,
            "headers": copy.deepcopy(headers),
        })
        raise requests.Timeout("SIEM timeout")


class SiemPublisherTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "event_id": "IDS-P005-203.0.113.9-20261123T105900Z",
            "timestamp": "2026-11-23T11:00:20Z",
            "source": "ids",
            "event_type": "endpoint_scan",
            "severity": "high",
            "title": "Posible escaneo de endpoints",
            "description": "Prueba",
            "details": {"rule_id": "P005", "target_ips": ["10.0.0.1"]},
        }

    def make_provider(self, session, clock=None):
        return IdentityTokenProvider(
            identity_url="http://identity.test",
            username="servicio-ids",
            password="test-password",
            session=session,
            clock=clock,
        )

    def test_409_is_permanent_reject_and_not_queued(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="token-1"),
                FakeResponse(
                    status_code=409,
                    text='{"code":"EVENT_ID_CONFLICT","message":"duplicate event"}',
                )
            ])

            with self.assertLogs("util.siem_publisher", level="ERROR") as captured:
                sent = publish_and_queue(
                    self.event,
                    siem_url="http://siem/events",
                    session=session,
                    pending_path=pending_path,
                    retries=0,
                    retry_delay=0,
                    token_provider=self.make_provider(session),
                )

            self.assertFalse(sent)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))
            self.assertIn("Rechazo definitivo", "\n".join(captured.output))
            self.assertIn("EVENT_ID_CONFLICT", "\n".join(captured.output))

    def test_503_is_queued_with_original_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="token-1"),
                FakeResponse(status_code=503, text="not ready")
            ])

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=self.make_provider(session),
            )

            self.assertFalse(sent)
            pending = __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            )
            self.assertEqual([self.event], pending)

    def test_timeout_is_queued_with_original_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = TimeoutSession()
            identity_session = FakeSession([FakeResponse(token="token-1")])

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=self.make_provider(identity_session),
            )

            self.assertFalse(sent)
            pending = __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            )
            self.assertEqual([self.event], pending)
            self.assertEqual([self.event], session.calls)

    def test_200_is_sent_and_removed_from_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="token-1"),
                FakeResponse(status_code=200, event_id=self.event["event_id"])
            ])

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=self.make_provider(session),
            )

            self.assertTrue(sent)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))
    def test_p005_is_common_schema_compatible(self):
        rule = EndpointScan(threshold="3", window="60")
        events = [
            {
                "timestamp": "Nov 20 10:00:00",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.1",
                "destination_port": 22,
            },
            {
                "timestamp": "Nov 20 10:00:10",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.2",
                "destination_port": 80,
            },
            {
                "timestamp": "Nov 20 10:00:20",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.3",
                "destination_port": 443,
            },
        ]

        with patch("patterns.endpoint_scan.datetime") as mocked_datetime:
            mocked_datetime.now.return_value.year = 2026
            mocked_datetime.strptime.side_effect = lambda value, fmt: __import__(
                "datetime"
            ).datetime.strptime(value, fmt)
            detections = rule.run(events)

        self.assertEqual(len(detections), 1)
        event = detections[0]
        self.assertEqual(set(event), {
            "event_id", "timestamp", "source", "event_type", "severity",
            "title", "description", "details",
        })
        self.assertEqual(event["source"], "ids")
        self.assertEqual(event["event_type"], "endpoint_scan")
        self.assertIn(event["severity"], {"medium", "high"})
        self.assertIn(event["details"]["rule_id"], {"P005"})
        self.assertTrue(event["event_id"].startswith("IDS-P005-"))
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_p004_is_common_schema_compatible(self):
        rule = BruteForce(threshold="3", window="60", usernames="2")
        events = [
            {
                "timestamp": "Nov 20 10:00:00",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "root",
                "service": "ssh",
            },
            {
                "timestamp": "Nov 20 10:00:10",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "admin",
                "service": "ssh",
            },
            {
                "timestamp": "Nov 20 10:00:20",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "admin",
                "service": "ssh",
            },
        ]

        with patch("patterns.brute_force.datetime") as mocked_datetime:
            mocked_datetime.now.return_value.year = 2026
            mocked_datetime.strptime.side_effect = lambda value, fmt: __import__(
                "datetime"
            ).datetime.strptime(value, fmt)
            detections = rule.run(events)

        self.assertEqual(len(detections), 1)
        event = detections[0]
        self.assertEqual(event["source"], "ids")
        self.assertEqual(event["event_type"], "brute_force")
        self.assertIn(event["severity"], {"medium", "high", "critical"})
        self.assertEqual(event["details"]["rule_id"], "P004")
        self.assertTrue(event["event_id"].startswith("IDS-P004-"))
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_retry_preserves_original_event_exactly(self):
        event = {
            "event_id": "IDS-P005-203.0.113.9-20261123T105900Z",
            "timestamp": "2026-11-23T11:00:20Z",
            "source": "ids",
            "event_type": "endpoint_scan",
            "severity": "high",
            "title": "Posible escaneo de endpoints",
            "description": "Prueba",
            "details": {"rule_id": "P005", "target_ips": ["10.0.0.1"]},
        }

        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="token-1"),
                FakeResponse(status_code=503, text="not ready"),
                FakeResponse(status_code=200, event_id=event["event_id"]),
            ])

            original = copy.deepcopy(event)
            token_provider = self.make_provider(session)
            self.assertFalse(publish_and_queue(
                event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=token_provider,
            ))
            self.assertEqual(event, original)

            retry_session = FakeSession([
                FakeResponse(status_code=200, event_id=event["event_id"])
            ])
            retry_pending(
                siem_url="http://siem/events",
                session=retry_session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=token_provider,
            )

            self.assertEqual(session.calls[0], original)
            self.assertEqual(retry_session.calls[0], original)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))

    def test_login_and_event_include_service_token(self):
        session = FakeSession([
            FakeResponse(token="g1-token"),
            FakeResponse(status_code=200, event_id=self.event["event_id"]),
        ])
        provider = self.make_provider(session)

        result = publish_event(
            self.event,
            siem_url="http://siem/events",
            session=session,
            token_provider=provider,
        )

        self.assertEqual(PUBLISH_SENT, result)
        self.assertEqual(
            "http://identity.test/auth/login", session.request_calls[0]["url"]
        )
        self.assertEqual(
            {"username": "servicio-ids", "password": "test-password"},
            session.request_calls[0]["json"],
        )
        self.assertEqual(
            {"Authorization": "Bearer g1-token"},
            session.request_calls[1]["headers"],
        )
        self.assertEqual(self.event, session.request_calls[1]["json"])

    def test_token_is_renewed_before_expiry(self):
        current_time = [1000]
        session = FakeSession([
            FakeResponse(token="token-1"),
            FakeResponse(status_code=200, event_id=self.event["event_id"]),
            FakeResponse(token="token-2"),
            FakeResponse(status_code=200, event_id=self.event["event_id"]),
        ])
        provider = self.make_provider(session, clock=lambda: current_time[0])

        self.assertEqual(
            PUBLISH_SENT,
            publish_event(self.event, session=session, token_provider=provider),
        )
        current_time[0] += 30 * 60 - 2 * 60
        self.assertEqual(
            PUBLISH_SENT,
            publish_event(self.event, session=session, token_provider=provider),
        )

        login_calls = [
            call for call in session.request_calls
            if call["url"].endswith("/auth/login")
        ]
        event_calls = [
            call for call in session.request_calls
            if not call["url"].endswith("/auth/login")
        ]
        self.assertEqual(2, len(login_calls))
        self.assertEqual("Bearer token-1", event_calls[0]["headers"]["Authorization"])
        self.assertEqual("Bearer token-2", event_calls[1]["headers"]["Authorization"])

    def test_401_logs_in_again_and_retries_same_event_once(self):
        session = FakeSession([
            FakeResponse(token="old-token"),
            FakeResponse(status_code=401),
            FakeResponse(token="new-token"),
            FakeResponse(status_code=200, event_id=self.event["event_id"]),
        ])
        provider = self.make_provider(session)
        original = copy.deepcopy(self.event)

        result = publish_event(
            self.event,
            session=session,
            token_provider=provider,
        )

        event_calls = [
            call for call in session.request_calls
            if not call["url"].endswith("/auth/login")
        ]
        self.assertEqual(PUBLISH_SENT, result)
        self.assertEqual(2, len(event_calls))
        self.assertEqual([original, original], [call["json"] for call in event_calls])
        self.assertEqual(
            ["Bearer old-token", "Bearer new-token"],
            [call["headers"]["Authorization"] for call in event_calls],
        )

    def test_second_401_is_queued_without_an_infinite_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="old-token"),
                FakeResponse(status_code=401),
                FakeResponse(token="new-token"),
                FakeResponse(status_code=401),
            ])

            with self.assertLogs("util.siem_publisher", level="ERROR") as captured:
                sent = publish_and_queue(
                    self.event,
                    session=session,
                    pending_path=pending_path,
                    retry_delay=0,
                    token_provider=self.make_provider(session),
                )

            self.assertFalse(sent)
            self.assertEqual(2, len(session.calls))
            self.assertEqual([self.event], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))
            self.assertIn("volvió a responder 401", "\n".join(captured.output))

    def test_401_then_failed_login_is_queued_without_resending_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(token="old-token"),
                FakeResponse(status_code=401),
                FakeResponse(status_code=401),
            ])

            sent = publish_and_queue(
                self.event,
                session=session,
                pending_path=pending_path,
                retry_delay=0,
                token_provider=self.make_provider(session),
            )

            self.assertFalse(sent)
            self.assertEqual(1, len(session.calls))
            self.assertEqual([self.event], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))

    def test_missing_credentials_fail_closed_and_queue_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            siem_session = FakeSession([])
            provider = IdentityTokenProvider(
                identity_url="http://identity.test",
                username="servicio-ids",
                password="",
                session=siem_session,
            )

            sent = publish_and_queue(
                self.event,
                session=siem_session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
                token_provider=provider,
            )

            self.assertFalse(sent)
            self.assertEqual([], siem_session.request_calls)
            self.assertEqual([self.event], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))


if __name__ == "__main__":
    unittest.main()

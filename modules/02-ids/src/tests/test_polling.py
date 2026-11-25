import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from util import health
from util.siem_publisher import publish_and_queue, retry_pending


class PollingTests(unittest.TestCase):
    def test_post_logs_appends_only_new_records(self):
        with tempfile.TemporaryDirectory() as directory:
            ids_path = Path(directory) / "received_ids.json"
            log_path = Path(directory) / "received.log"
            with patch.object(health, "RECEIVED_IDS_FILE", ids_path), patch.object(
                health, "RECEIVED_LOG_FILE", log_path
            ):
                client = health.app.test_client()
                first = {
                    "id": "log-1",
                    "raw_line": "Apr 20 13:51:02 host sshd: first",
                }
                second = {
                    "id": "log-2",
                    "raw_line": "Apr 20 13:51:03 host sshd: second",
                }

                self.assertEqual(
                    client.post(
                        "/logs", json={"source": "test", "logs": [first]}
                    ).status_code,
                    202,
                )
                health.mark_records_processed([first["raw_line"]])
                log_path.write_text("", encoding="utf-8")
                self.assertEqual(
                    client.post(
                        "/logs", json={"source": "test", "logs": [second]}
                    ).status_code,
                    202,
                )

                self.assertEqual(
                    log_path.read_text(encoding="utf-8").splitlines(),
                    [second["raw_line"]],
                )
                records = json.loads(ids_path.read_text(encoding="utf-8"))
                self.assertTrue(records["log-1"]["processed"])
                self.assertFalse(records["log-2"]["processed"])

    def test_process_log_batch_reads_and_truncates_under_one_lock(self):
        class TrackingLock:
            def __init__(self):
                self.entered = 0
                self.exited = 0

            def __enter__(self):
                self.entered += 1

            def __exit__(self, *_args):
                self.exited += 1

        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "received.log"
            log_path.write_text("invalid syslog line\n", encoding="utf-8")
            lock = TrackingLock()
            rule = type("Rule", (), {"enabled": True, "run": lambda self, events: []})()
            storage = type("Storage", (), {"save_many": lambda self, events: None})()

            with patch.object(main, "file_lock", lock), patch.object(
                main, "mark_records_processed"
            ), patch.object(main, "_append_events"), patch.object(
                main, "retry_pending"
            ):
                self.assertTrue(main._process_log_batch(log_path, [rule], storage))

            self.assertEqual(lock.entered, 1)
            self.assertEqual(lock.exited, 1)
            self.assertEqual(log_path.read_bytes(), b"")

    def test_poll_interval_validation(self):
        with patch.dict(os.environ, {"IDS_POLL_INTERVAL": "2.5"}):
            self.assertEqual(main._get_poll_interval(), 2.5)
        with patch.dict(os.environ, {"IDS_POLL_INTERVAL": "-1"}):
            self.assertEqual(main._get_poll_interval(), 5)
        with patch.dict(os.environ, {"IDS_POLL_INTERVAL": "invalid"}):
            self.assertEqual(main._get_poll_interval(), 5)

    def test_polling_stops_when_event_is_set(self):
        stop_event = threading.Event()
        stop_event.set()

        with patch.object(main, "_process_log_batch", return_value=False):
            started = time.monotonic()
            main._poll_logs(stop_event, [], None, Path("unused.log"), 60)

        self.assertLess(time.monotonic() - started, 1)

    def test_events_are_accumulated(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.json"
            events_path.write_text(json.dumps([{"event_id": "old"}]), encoding="utf-8")

            main._append_events(events_path, [{"event_id": "new"}])

            self.assertEqual(
                json.loads(events_path.read_text(encoding="utf-8")),
                [{"event_id": "old"}, {"event_id": "new"}],
            )

    def test_failed_batch_is_backed_up(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "received.log"
            log_path.write_text("invalid syslog line\n", encoding="utf-8")
            rule = type(
                "Rule",
                (),
                {
                    "enabled": True,
                    "run": lambda self, events: (_ for _ in ()).throw(
                        RuntimeError("rule failure")
                    ),
                },
            )()
            storage = type("Storage", (), {"save_many": lambda self, events: None})()

            with patch.object(main, "mark_records_processed"):
                self.assertTrue(main._process_log_batch(log_path, [rule], storage))

            backup = Path(directory) / "failed_batches.log"
            self.assertIn("rule failure", backup.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

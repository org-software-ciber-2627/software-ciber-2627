import os
import tempfile
import unittest
from unittest.mock import patch

import app


class SoarIdempotencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = tempfile.NamedTemporaryFile(delete=False)
        self.database.close()
        self.database_path = self.database.name

    def tearDown(self) -> None:
        os.unlink(self.database_path)

    def test_same_alert_is_stored_only_once(self) -> None:
        alert = {"alert_id": "siem-1", "severity": "high"}
        with patch.object(app, "DATABASE_PATH", self.database_path):
            self.assertTrue(app.save_alert(alert))
            self.assertFalse(app.save_alert(alert))
            self.assertEqual(len(app.list_incidents()), 1)

    def test_alert_without_id_has_deterministic_key(self) -> None:
        alert = {
            "IP_origen": "192.0.2.10",
            "tipo_evento": "login_failed",
            "timestamp": "2026-10-09T16:00:00Z",
        }
        with patch.object(app, "DATABASE_PATH", self.database_path):
            self.assertTrue(app.save_alert(alert))
            self.assertFalse(app.save_alert(dict(alert)))


if __name__ == "__main__":
    unittest.main()

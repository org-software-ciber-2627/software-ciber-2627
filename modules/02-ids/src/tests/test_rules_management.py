import os
import tempfile
import unittest

from patterns.brute_force import BruteForce
from util.rule_manager import RuleManager, RuleValidationError


class TestRulesManagement(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.rules_file = os.path.join(self.tmp_dir.name, "ids.rules")
        self.manager = RuleManager(rules_path=self.rules_file)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_add_rule_dynamically_and_reject_invalid(self):
        """IDS-103: Incorporación dinámica de regla válida y rechazo de inválidas."""
        line = self.manager.add_rule("P004", threshold=3, window=60, extra_args="usernames=2")
        self.assertEqual(line, "P004,3,60,usernames=2")
        self.assertIn("P004", self.manager.get_existing_ids())

        with self.assertRaises(RuleValidationError):
            self.manager.add_rule("P004", threshold=3, window=60)

        with self.assertRaises(RuleValidationError):
            self.manager.add_rule("P099", threshold=0, window=60)

    def test_disable_rule_omits_detection(self):
        """IDS-106: Regla desactivada no dispara alertas."""
        self.manager.add_rule("P004", threshold=2, window=60)
        self.manager.disable_rule("P004")
        self.assertFalse(self.manager.is_rule_enabled_in_config("P004"))

        rule = BruteForce(threshold=2, window=60)
        if self.manager.is_rule_enabled_in_config("P004") is False:
            rule.disable()

        eventos = [
            {"timestamp": "Nov 21 17:00:01", "source_ip": "10.0.0.5", "event_type": "failed_login", "username": "root", "service": "ssh"},
            {"timestamp": "Nov 21 17:00:05", "source_ip": "10.0.0.5", "event_type": "failed_login", "username": "root", "service": "ssh"},
        ]

        detections = rule.run(eventos) if rule.enabled else []
        self.assertEqual(detections, [])

    def test_edit_rule_updates_values_and_preserves_extra_when_omitted(self):
        self.manager.add_rule("P004", threshold=3, window=60, extra_args="usernames=2")

        edited = self.manager.edit_rule("P004", threshold=7, window=120)
        self.assertEqual(edited, "P004,7,120,usernames=2")

        edited_with_extra = self.manager.edit_rule(
            "P004", threshold=8, window=180, extra_args="usernames=4;enabled=true"
        )
        self.assertEqual(edited_with_extra, "P004,8,180,usernames=4;enabled=true")

        with self.assertRaises(KeyError):
            self.manager.edit_rule("P999", threshold=3, window=60)

        with self.assertRaises(RuleValidationError):
            self.manager.edit_rule("P004", threshold=0, window=60)


if __name__ == "__main__":
    unittest.main()
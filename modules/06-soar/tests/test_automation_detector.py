import unittest

from soar.models.incident import Incident
from soar.services.automation_detector import evaluate_automation


class TestAutomationDetector(unittest.TestCase):

    def create_incident(
        self,
        event_type="fuerza_bruta",
        source_ip="192.168.1.10",
    ):
        return Incident(
            incident_id="INC-001",
            alert_id="ALT-001",
            event_type=event_type,
            severity="high",
            source_ip=source_ip,
            status="open",
            created_at="2026-10-27T12:00:00Z",
        )

    def test_brute_force_with_source_ip_is_automatable(self):
        incident = self.create_incident()

        decision = evaluate_automation(incident)

        self.assertTrue(decision.automatable)
        self.assertEqual(decision.playbook, "brute_force")

    def test_brute_force_without_source_ip_is_not_automatable(self):
        incident = self.create_incident(source_ip=None)

        decision = evaluate_automation(incident)

        self.assertFalse(decision.automatable)
        self.assertIsNone(decision.playbook)

    def test_unknown_event_is_not_automatable(self):
        incident = self.create_incident(
            event_type="vulnerability_detected"
        )

        decision = evaluate_automation(incident)

        self.assertFalse(decision.automatable)
        self.assertIsNone(decision.playbook)

    def test_detector_does_not_modify_incident(self):
        incident = self.create_incident()
        original = incident.model_copy(deep=True)

        evaluate_automation(incident)

        self.assertEqual(incident, original)


if __name__ == "__main__":
    unittest.main()

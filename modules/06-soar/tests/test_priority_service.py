import unittest
from soar.services.priority_service import prioritize_incident, calculate_priority, prioritize
from soar.models.alert_priority import PriorityLevel
from soar.models.incident import Incident


class TestPriorityService(unittest.TestCase):

    def test_critical_by_severity(self):
        incident = {"id": "INC-001", "severity": "critical", "event_type": "port_scan"}
        res = prioritize_incident(incident)
        self.assertEqual(res["priority"], PriorityLevel.CRITICAL.value)

    def test_critical_by_event_type(self):
        incident = {"id": "INC-002", "severity": "medium", "event_type": "ransomware_detected"}
        res = prioritize_incident(incident)
        self.assertEqual(res["priority"], PriorityLevel.CRITICAL.value)

    def test_high_medium_low_mapping(self):
        self.assertEqual(calculate_priority({"severity": "high", "event_type": "fuerza_bruta"}), PriorityLevel.HIGH)
        self.assertEqual(calculate_priority({"severity": "medium", "event_type": "unknown"}), PriorityLevel.MEDIUM)
        self.assertEqual(calculate_priority({"severity": "low", "event_type": "info"}), PriorityLevel.LOW)

    def test_unknown_or_missing_severity_defaults_to_low(self):
        incident = {"id": "INC-003", "event_type": "unknown_event"}
        res = prioritize_incident(incident)
        self.assertEqual(res["priority"], PriorityLevel.LOW.value)

    def test_incident_fields_are_preserved(self):
        incident = {"id": "INC-004", "source_ip": "192.168.1.50", "severity": "high"}
        res = prioritize_incident(incident)
        self.assertEqual(res["id"], "INC-004")
        self.assertEqual(res["source_ip"], "192.168.1.50")
        self.assertEqual(res["priority"], PriorityLevel.HIGH.value)

    def test_prioritize_returns_incident_copy_with_priority(self):
        incident = Incident(
            incident_id="INC-005", alert_id="ALT-005", event_type="fuerza_bruta",
            severity="high", source_ip="192.168.1.50", status="open",
            created_at="2026-10-27T12:00:00Z",
        )
        res = prioritize(incident)
        self.assertEqual(res.priority, PriorityLevel.HIGH.value)
        self.assertIsNone(incident.priority)


if __name__ == "__main__":
    unittest.main()
    
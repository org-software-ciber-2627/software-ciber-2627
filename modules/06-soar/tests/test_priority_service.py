import unittest
from soar.services.priority_service import prioritize_incident, calculate_priority
from soar.models.alert_priority import PriorityLevel


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
        self.assertEqual(calculate_priority({"severity": "high", "event_type": "brute_force"}), PriorityLevel.HIGH)
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


if __name__ == "__main__":
    unittest.main()
    
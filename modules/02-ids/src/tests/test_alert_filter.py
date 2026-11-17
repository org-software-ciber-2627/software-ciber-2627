import unittest
import sys
# Allows python to import from the "src" directory, dirty fix
sys.path.append(sys.path[0]+"/..")
from util.alert_filter import filter_alerts_by_ip, is_valid_ip, filter_alerts_by_event_type, filter_alerts_by_severity


class AlertFilterTests(unittest.TestCase):
    alerts = [
        {
            "event_type": "failed_login",
            "severity": "medium",
            "details": {"source_ip": "192.168.1.10"}
        },
        {
            "event_type": "endpoint_scan",
            "severity": "medium",
            "details": {"source_ip": "10.0.0.5"}
        },
        {
            "event_type": "brute_force",
            "severity": "high",
            "details": {"source_ip": "192.168.1.10"}
        },
        {
            "event_type": "failed_login",
            "severity": "critical",
            "details": {"source_ip": "192.168.1.20"}
        }
    ]

    def test_is_valid_ip_correcta(self):
        self.assertTrue(is_valid_ip("192.168.1.10"))

    def test_is_valid_ip_incorrecta(self):
        self.assertFalse(is_valid_ip("256.256.256.256"))
        self.assertFalse(is_valid_ip("ip-inventada"))

    def test_filter_alerts_ip_match(self):
        self.assertEqual(
            filter_alerts_by_ip(self.alerts, "192.168.1.10"),
            [self.alerts[0], self.alerts[2]],
        )

    def test_filter_alerts_ip_no_match(self):
        self.assertEqual(filter_alerts_by_ip(self.alerts, "192.168.1.11"), [])

    def test_filter_alerts_invalid_ip(self):
        with self.assertRaises(ValueError):
            filter_alerts_by_ip(self.alerts, "256.256.256.256")

    def test_filter_alerts_event_type(self):
        self.assertEqual(
            filter_alerts_by_event_type(self.alerts, "failed_login"),
            [self.alerts[0], self.alerts[3]])

    def test_filter_alerts_event_type_no_match(self):
        self.assertEqual(filter_alerts_by_event_type(self.alerts, "port_scan"), [])


    def test_filter_alerts_severity(self):
        self.assertEqual(
            filter_alerts_by_severity(self.alerts, "medium"),
            [self.alerts[0], self.alerts[1]]
        )

    def test_filter_alerts_severity_no_match(self):
        self.assertEqual(filter_alerts_by_severity(self.alerts, "low"), [])

    def test_filter_alerts_severity_invalid(self):
        with self.assertRaises(ValueError):
            filter_alerts_by_severity(self.alerts, "lowest")

    def test_filter_alerts_combined_filters(self):
        alerts = filter_alerts_by_ip(self.alerts, "192.168.1.10")
        self.assertEqual(
            filter_alerts_by_severity(alerts, "medium"),
            [self.alerts[0]]
        )

    def test_filter_alerts_combined_filters_no_match(self):
        alerts = filter_alerts_by_ip(self.alerts, "192.168.1.10")
        self.assertEqual(
            filter_alerts_by_severity(alerts, "low"),
            []
        )

if __name__ == "__main__":
    unittest.main()

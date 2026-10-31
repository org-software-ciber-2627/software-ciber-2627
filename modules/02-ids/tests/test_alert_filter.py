import unittest

from util.alert_filter import filter_alerts_by_ip, is_valid_ip


class AlertFilterTests(unittest.TestCase):
    def test_is_valid_ip_correcta(self):
        self.assertTrue(is_valid_ip("192.168.1.10"))

    def test_is_valid_ip_incorrecta(self):
        self.assertFalse(is_valid_ip("256.256.256.256"))
        self.assertFalse(is_valid_ip("ip-inventada"))

    def test_filter_alerts_match(self):
        alerts = [
            {"source_ip": "192.168.1.10", "event_type": "failed_login"},
            {"source_ip": "10.0.0.5", "event_type": "port_scan"},
            {"source_ip": "192.168.1.10", "event_type": "brute_force"},
        ]

        self.assertEqual(
            filter_alerts_by_ip(alerts, "192.168.1.10"),
            [alerts[0], alerts[2]],
        )

    def test_filter_alerts_no_match(self):
        alerts = [
            {"source_ip": "192.168.1.10"},
            {"source_ip": "10.0.0.5"},
            {"source_ip": "172.16.0.2"},
        ]

        self.assertEqual(filter_alerts_by_ip(alerts, "192.168.1.11"), [])

    def test_filter_alerts_invalid_ip(self):
        with self.assertRaises(ValueError):
            filter_alerts_by_ip([], "256.256.256.256")


if __name__ == "__main__":
    unittest.main()

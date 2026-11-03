import unittest

from soar.models.incident import Incident
from soar.repositories.incident_repository import IncidentRepository
from soar.services.incident_service import IncidentService


class TestIncidentService(unittest.TestCase):
    def test_list_incidents_returns_empty_list_when_no_incidents_exist(self):
        repository = IncidentRepository()
        service = IncidentService(repository)

        result = service.list_incidents()

        self.assertEqual(result, [])

    def test_list_incidents_returns_all_registered_incidents(self):
        incidents = [
            Incident(
                incident_id="INC-001",
                alert_id="SIEM-ALERT-EJEMPLO-001",
                event_type="port_scan",
                severity="medium",
                source_ip="192.168.1.50",
                status="open",
                created_at="2026-09-22T18:30:20Z",
            ),
            Incident(
                incident_id="INC-002",
                alert_id="SIEM-ALERT-EJEMPLO-002",
                event_type="fuerza_bruta",
                severity="high",
                source_ip="192.168.1.60",
                status="in_progress",
                created_at="2026-09-22T18:31:00Z",
            ),
        ]

        repository = IncidentRepository(incidents)
        service = IncidentService(repository)

        result = service.list_incidents()

        self.assertEqual(len(result), 2)

    def test_list_incidents_preserves_incident_data(self):
        incident = Incident(
            incident_id="INC-001",
            alert_id="SIEM-ALERT-EJEMPLO-001",
            event_type="port_scan",
            severity="medium",
            source_ip="192.168.1.50",
            status="open",
            created_at="2026-09-22T18:30:20Z",
        )

        repository = IncidentRepository([incident])
        service = IncidentService(repository)

        result = service.list_incidents()

        self.assertEqual(result[0], incident)
        self.assertEqual(result[0].incident_id, "INC-001")
        self.assertEqual(result[0].alert_id, "SIEM-ALERT-EJEMPLO-001")
        self.assertEqual(result[0].event_type, "port_scan")
        self.assertEqual(result[0].severity, "medium")
        self.assertEqual(result[0].source_ip, "192.168.1.50")
        self.assertEqual(result[0].status, "open")
        self.assertEqual(result[0].created_at, "2026-09-22T18:30:20Z")
        self.assertIsNone(result[0].resolved_at)


if __name__ == "__main__":
    unittest.main()

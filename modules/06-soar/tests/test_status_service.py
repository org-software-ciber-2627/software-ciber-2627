import unittest
from datetime import datetime, timezone

from soar.models.incident import Incident
from soar.models.incident_status import IncidentStatus
from soar.repositories.status_history_repository import StatusHistoryRepository
from soar.services.status_service import (
    IncidentClosedError,
    InvalidTransitionError,
    MissingJustificationError,
    MissingResolutionReasonError,
    StatusService,
)


FIXED_TIME = datetime(2026, 10, 27, 16, 30, tzinfo=timezone.utc)


class TestStatusService(unittest.TestCase):
    def create_incident(self, status="open"):
        return Incident(
            incident_id="INC-001",
            alert_id="SIEM-ALERT-EJEMPLO-001",
            event_type="port_scan",
            severity="medium",
            source_ip="192.168.1.50",
            status=status,
            created_at="2026-09-22T18:30:20Z",
        )

    def create_service(self):
        repository = StatusHistoryRepository()
        service = StatusService(repository, clock=lambda: FIXED_TIME)
        return service, repository

    def test_open_to_in_progress_updates_status(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        result = service.change_status(
            incident, IncidentStatus.IN_PROGRESS, "Investigation started"
        )

        self.assertEqual(result.status, "in_progress")

    def test_complete_status_chain(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        in_progress = service.change_status(
            incident, "in_progress", "Investigation started"
        )
        contained = service.change_status(
            in_progress, IncidentStatus.CONTAINED, "Threat contained"
        )
        closed = service.change_status(
            contained,
            "closed",
            "Incident resolved",
            resolution_reason="Root cause fixed",
        )

        self.assertEqual(closed.status, "closed")

    def test_contained_can_be_reactivated(self):
        service, _ = self.create_service()
        incident = self.create_incident("contained")

        result = service.change_status(
            incident, "in_progress", "Additional activity detected"
        )

        self.assertEqual(result.status, "in_progress")

    def test_open_to_contained_is_not_allowed(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        with self.assertRaises(InvalidTransitionError):
            service.change_status(incident, "contained", "Skipping investigation")

    def test_empty_and_whitespace_justifications_are_rejected(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        for justification in ("", "   "):
            with self.subTest(justification=repr(justification)):
                with self.assertRaises(MissingJustificationError):
                    service.change_status(incident, "in_progress", justification)

    def test_closing_without_resolution_reason_is_rejected(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        with self.assertRaises(MissingResolutionReasonError):
            service.change_status(incident, "closed", "Incident resolved")

    def test_closing_with_resolution_reason_sets_resolved_at(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        result = service.change_status(
            incident,
            "closed",
            "Incident resolved",
            resolution_reason="Root cause fixed",
        )

        self.assertEqual(result.status, "closed")
        self.assertEqual(service.get_resolved_at(incident.incident_id), FIXED_TIME)

    def test_any_change_on_closed_incident_is_rejected(self):
        service, _ = self.create_service()
        incident = self.create_incident("closed")

        with self.assertRaises(IncidentClosedError):
            service.change_status(incident, "open", "Reopening incident")

    def test_history_contains_change_data_in_order(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        in_progress = service.change_status(
            incident, "in_progress", "Investigation started"
        )
        contained = service.change_status(
            in_progress, "contained", "Threat contained"
        )
        service.change_status(
            contained,
            "closed",
            "Incident resolved",
            resolution_reason="Root cause fixed",
        )

        history = service.get_history(incident.incident_id)

        self.assertEqual(
            [(change.from_status, change.to_status) for change in history],
            [
                (IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS),
                (IncidentStatus.IN_PROGRESS, IncidentStatus.CONTAINED),
                (IncidentStatus.CONTAINED, IncidentStatus.CLOSED),
            ],
        )
        self.assertEqual(
            [change.justification for change in history],
            ["Investigation started", "Threat contained", "Incident resolved"],
        )
        self.assertEqual([change.changed_at for change in history], [FIXED_TIME] * 3)

    def test_change_status_does_not_mutate_original_incident(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        result = service.change_status(incident, "in_progress", "Investigation started")

        self.assertEqual(incident.status, "open")
        self.assertEqual(result.status, "in_progress")
        self.assertIsNot(result, incident)

    def test_failed_transition_does_not_add_to_history(self):
        service, _ = self.create_service()
        incident = self.create_incident()

        with self.assertRaises(InvalidTransitionError):
            service.change_status(incident, "contained", "Skipping investigation")

        self.assertEqual(service.get_history(incident.incident_id), [])


if __name__ == "__main__":
    unittest.main()

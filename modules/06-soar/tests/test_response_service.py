import re
import unittest
from datetime import datetime, timezone

from pydantic import ValidationError

from soar.models.executed_response import ExecutedResponse
from soar.models.incident import Incident
from soar.repositories.response_repository import ResponseRepository
from soar.services.response_service import ResponseService


EXECUTED_AT = datetime(2026, 10, 27, 12, 0, 5, tzinfo=timezone.utc)
FINISHED_AT = datetime(2026, 10, 27, 12, 0, 6, tzinfo=timezone.utc)


def build_response(**overrides) -> ExecutedResponse:
    data = {
        "incident_id": "INC-001",
        "playbook": "brute_force",
        "action": "notify",
        "executed_at": EXECUTED_AT,
    }
    data.update(overrides)
    return ExecutedResponse(**data)


class TestExecutedResponseModel(unittest.TestCase):
    def test_valid_response_uses_default_values(self):
        response = build_response()

        self.assertRegex(response.response_id, re.compile(r"^RES-[0-9A-F]{6}$"))
        self.assertEqual(response.status, "pending")
        self.assertEqual(response.triggered_by, "automatic")
        self.assertIsNone(response.finished_at)
        self.assertIsNone(response.message)
        self.assertIsNone(response.error)
        self.assertEqual(response.details, {})

    def test_response_ids_are_unique(self):
        self.assertNotEqual(build_response().response_id, build_response().response_id)

    def test_status_and_origin_are_normalized_to_lowercase(self):
        response = build_response(status="SUCCESS", triggered_by="Manual")

        self.assertEqual(response.status, "success")
        self.assertEqual(response.triggered_by, "manual")

    def test_invalid_status_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_response(status="contained")

    def test_invalid_origin_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_response(triggered_by="scheduler")

    def test_details_default_is_not_shared_between_responses(self):
        first = build_response()
        second = build_response()

        first.details["channel"] = "grupo-7"

        self.assertEqual(second.details, {})


class TestResponseService(unittest.TestCase):
    def test_list_responses_by_incident_returns_empty_list_when_incident_has_no_responses(self):
        service = ResponseService(ResponseRepository())

        result = service.list_responses_by_incident("INC-001")

        self.assertEqual(result, [])

    def test_list_responses_by_incident_returns_empty_list_for_unknown_incident(self):
        service = ResponseService(ResponseRepository())
        service.register_response(build_response(incident_id="INC-001"))

        result = service.list_responses_by_incident("INC-999")

        self.assertEqual(result, [])

    def test_register_response_stores_response(self):
        service = ResponseService(ResponseRepository())
        response = build_response()

        registered = service.register_response(response)

        self.assertEqual(registered, response)
        self.assertEqual(service.list_responses(), [response])

    def test_register_response_preserves_response_data(self):
        service = ResponseService(ResponseRepository())
        response = build_response(
            status="success",
            triggered_by="manual",
            finished_at=FINISHED_AT,
            message="Incidente notificado al grupo 7",
            error=None,
            details={"recipient": "grupo-7"},
        )

        service.register_response(response)
        result = service.list_responses_by_incident("INC-001")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].response_id, response.response_id)
        self.assertEqual(result[0].incident_id, "INC-001")
        self.assertEqual(result[0].playbook, "brute_force")
        self.assertEqual(result[0].action, "notify")
        self.assertEqual(result[0].status, "success")
        self.assertEqual(result[0].triggered_by, "manual")
        self.assertEqual(result[0].executed_at, EXECUTED_AT)
        self.assertEqual(result[0].finished_at, FINISHED_AT)
        self.assertEqual(result[0].message, "Incidente notificado al grupo 7")
        self.assertIsNone(result[0].error)
        self.assertEqual(result[0].details, {"recipient": "grupo-7"})

    def test_failed_response_keeps_error(self):
        service = ResponseService(ResponseRepository())
        response = build_response(status="failed", error="Grupo 7 no disponible")

        service.register_response(response)
        result = service.list_responses_by_incident("INC-001")

        self.assertEqual(result[0].status, "failed")
        self.assertEqual(result[0].error, "Grupo 7 no disponible")

    def test_incident_can_have_several_responses(self):
        service = ResponseService(ResponseRepository())
        notify = build_response(action="notify", status="success")
        block_ip = build_response(action="block_ip", status="skipped")

        service.register_response(notify)
        service.register_response(block_ip)
        result = service.list_responses_by_incident("INC-001")

        self.assertEqual(result, [notify, block_ip])

    def test_responses_stay_associated_with_their_incident(self):
        service = ResponseService(ResponseRepository())
        first = build_response(incident_id="INC-001")
        second = build_response(incident_id="INC-002")
        third = build_response(incident_id="INC-001", action="block_ip")

        for response in (first, second, third):
            service.register_response(response)

        self.assertEqual(service.list_responses_by_incident("INC-001"), [first, third])
        self.assertEqual(service.list_responses_by_incident("INC-002"), [second])
        self.assertEqual(len(service.list_responses()), 3)

    def test_registering_response_does_not_modify_incident(self):
        incident = Incident(
            incident_id="INC-001",
            alert_id="SIEM-ALERT-EJEMPLO-002",
            event_type="fuerza_bruta",
            severity="high",
            source_ip="192.168.1.50",
            status="open",
            created_at="2026-10-27T12:00:00Z",
        )
        snapshot = incident.model_dump()
        service = ResponseService(ResponseRepository())

        service.register_response(build_response(incident_id=incident.incident_id, status="success"))

        self.assertEqual(incident.model_dump(), snapshot)

    def test_list_responses_returns_copy_of_stored_responses(self):
        service = ResponseService(ResponseRepository())
        service.register_response(build_response())

        service.list_responses().clear()

        self.assertEqual(len(service.list_responses()), 1)


if __name__ == "__main__":
    unittest.main()

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any, Optional

from soar.models.executed_response import ExecutedResponse
from soar.models.incident import Incident
from soar.models.incident_status import IncidentStatus
from soar.models.playbook import BRUTE_FORCE_PLAYBOOK, BruteForcePlaybookInput
from soar.normalization.parser import parse_and_normalize_alert
from soar.repositories.incident_repository import SqliteIncidentRepository
from soar.repositories.response_repository import SqliteResponseRepository
from soar.repositories.status_history_repository import SqliteStatusHistoryRepository
from soar.services.automation_detector import evaluate_automation
from soar.services.playbook_service import PlaybookService
from soar.services.priority_service import prioritize
from soar.services.response_mapper import responses_from_playbook_output
from soar.services.response_service import ResponseService
from soar.services.status_service import StatusService

logger = logging.getLogger("soar")


class IncidentNotFoundError(Exception):
    pass


class SoarPipeline:
    """
    Orquesta el flujo del Sprint 2 sobre el SQLite del módulo:
    normalización → idempotencia → Incident → HU5 → HU13 → HU14 → HU15 → HU6.
    """

    def __init__(
        self,
        database_path: str,
        register_alert: Callable[[dict[str, Any]], bool],
        alert_key: Callable[[dict[str, Any]], str],
        playbook_service: Optional[PlaybookService] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._register_alert = register_alert
        self._alert_key = alert_key
        self._incidents = SqliteIncidentRepository(database_path)
        self._responses = ResponseService(SqliteResponseRepository(database_path))
        self._status = StatusService(SqliteStatusHistoryRepository(database_path), clock)
        self._playbooks = playbook_service or PlaybookService()

    def process_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Procesa una alerta del SIEM. Devuelve {"result": created | ignored | rejected, "automated": bool}.
        """
        try:
            incident = parse_and_normalize_alert(alert)
        except ValueError as error:
            logger.warning("Alerta rechazada por no cumplir el contrato: %s", error)
            return {"result": "rejected", "automated": False}

        # Idempotencia con la tabla incidents de app.py (registra también el log de duplicado)
        if not self._register_alert(alert):
            return {"result": "ignored", "automated": False}

        incident = prioritize(incident.model_copy(update={"alert_key": self._alert_key(alert)}))
        self._incidents.save(incident)

        decision = evaluate_automation(incident)
        responses: list[ExecutedResponse] = []
        automated = False
        if decision.automatable and not self._responses.list_responses_by_incident(incident.incident_id):
            responses = self._run_playbook(incident, decision.playbook, decision.reason)
            automated = bool(responses)
            successful = [response.action for response in responses if response.status == "success"]
            if successful:
                incident = self._status.change_status(
                    incident,
                    IncidentStatus.IN_PROGRESS,
                    f"Respuesta automática ejecutada: {', '.join(successful)}",
                )
                self._incidents.save(incident)

        logger.info(
            "Alerta procesada: incidente %s, prioridad %s, automatizable %s (%s), respuestas %s, estado %s",
            incident.incident_id,
            incident.priority,
            decision.automatable,
            decision.reason,
            [f"{response.action}={response.status}" for response in responses],
            incident.status,
        )
        return {"result": "created", "automated": automated}

    def _run_playbook(self, incident: Incident, playbook: Optional[str], reason: str) -> list[ExecutedResponse]:
        if playbook != BRUTE_FORCE_PLAYBOOK:
            logger.warning("Playbook sin implementación: %s", playbook)
            return []
        output = self._playbooks.execute_brute_force_playbook(
            BruteForcePlaybookInput.from_incident(incident), reason=reason
        )
        responses = responses_from_playbook_output(output)
        for response in responses:
            self._responses.register_response(response)
        return responses

    def incident_views(self) -> dict[str, dict[str, Any]]:
        """
        Datos añadidos a GET /incidents, indexados por alert_key.
        applied_playbook es el playbook de las respuestas registradas, sea cual sea su status.
        """
        views = {}
        for incident in self._incidents.find_all():
            decision = evaluate_automation(incident)
            responses = self._responses.list_responses_by_incident(incident.incident_id)
            views[incident.alert_key] = {
                "incident_id": incident.incident_id,
                "alert_id": incident.alert_id,
                "event_type": incident.event_type,
                "severity": incident.severity,
                "priority": incident.priority,
                "source_ip": incident.source_ip,
                "status": incident.status,
                "created_at": incident.created_at,
                "resolved_at": incident.resolved_at,
                "applied_playbook": responses[0].playbook if responses else None,
                "automation": decision.model_dump(),
                "responses": [response.model_dump(mode="json") for response in responses],
            }
        return views

    def list_responses(self, incident_id: str) -> list[ExecutedResponse]:
        self._get_incident(incident_id)
        return self._responses.list_responses_by_incident(incident_id)

    def change_status(
        self,
        incident_id: str,
        new_status: str,
        justification: str,
        resolution_reason: Optional[str] = None,
    ) -> Incident:
        """
        Aplica HU6 a un incidente guardado. Al cerrarlo, rellena resolved_at con la fecha del cambio.
        """
        incident = self._status.change_status(
            self._get_incident(incident_id), new_status, justification, resolution_reason
        )
        if incident.status == IncidentStatus.CLOSED.value:
            incident = incident.model_copy(
                update={"resolved_at": self._status.get_resolved_at(incident_id).isoformat()}
            )
        return self._incidents.save(incident)

    def _get_incident(self, incident_id: str) -> Incident:
        incident = self._incidents.find_by_id(incident_id)
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        return incident

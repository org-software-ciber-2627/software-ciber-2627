from collections.abc import Callable
from datetime import datetime, timezone
from typing import Optional

from soar.models.incident import Incident
from soar.models.incident_status import IncidentStatus, is_transition_allowed
from soar.models.status_change import StatusChange
from soar.repositories.status_history_repository import StatusHistoryRepository


class InvalidTransitionError(Exception):
    pass


class MissingJustificationError(Exception):
    pass


class MissingResolutionReasonError(Exception):
    pass


class IncidentClosedError(Exception):
    pass


class StatusService:
    def __init__(
        self,
        history_repository: StatusHistoryRepository,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._history_repository = history_repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def change_status(
        self,
        incident: Incident,
        new_status: IncidentStatus | str,
        justification: str,
        resolution_reason: Optional[str] = None,
    ) -> Incident:
        current_status = IncidentStatus(incident.status)
        if current_status is IncidentStatus.CLOSED:
            raise IncidentClosedError("Closed incidents cannot change status")

        if not justification or not justification.strip():
            raise MissingJustificationError("A justification is required")

        target_status = IncidentStatus(new_status)
        if not is_transition_allowed(current_status, target_status):
            raise InvalidTransitionError(
                f"Transition from {current_status.value} to {target_status.value} "
                "is not allowed"
            )

        if target_status is IncidentStatus.CLOSED and (
            not resolution_reason or not resolution_reason.strip()
        ):
            raise MissingResolutionReasonError(
                "A resolution reason is required when closing an incident"
            )

        self._history_repository.add(
            StatusChange(
                incident_id=incident.incident_id,
                from_status=current_status,
                to_status=target_status,
                justification=justification,
                changed_at=self._clock(),
                resolution_reason=resolution_reason,
            )
        )
        return incident.model_copy(update={"status": target_status.value})

    def get_history(self, incident_id: str) -> list[StatusChange]:
        return self._history_repository.get_by_incident(incident_id)

    def get_resolved_at(self, incident_id: str) -> Optional[datetime]:
        for change in self.get_history(incident_id):
            if change.to_status is IncidentStatus.CLOSED:
                return change.changed_at
        return None

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from soar.models.incident import Incident

# Acciones que ejecuta el playbook de fuerza bruta en cada Sprint
BRUTE_FORCE_PLAYBOOK = "brute_force"
BRUTE_FORCE_ACTIONS = ["notify"]  # Sprint 3: block_ip y disable_account (equipo 1)

ACTION_STATUSES = {"success", "failed", "skipped"}
PLAYBOOK_STATUSES = {"COMPLETED", "FAILED", "PARTIAL"}


class BruteForcePlaybookInput(BaseModel):
    incident_id: str
    source_ip: str
    target_ip: Optional[str] = None

    service: str = "unknown"
    username: Optional[str] = None
    usernames: list[str] = Field(default_factory=list)

    failed_attempts: int = 1

    # Datos del incidente que se envían en la notificación al grupo 7
    event_type: str = "fuerza_bruta"
    severity: Optional[str] = None
    priority: Optional[str] = None
    detected_at: Optional[str] = None

    @classmethod
    def from_incident(cls, incident: Incident) -> "BruteForcePlaybookInput":
        """
        Construye la entrada del playbook a partir del Incident único del SOAR.
        """
        if incident.event_type not in {"fuerza_bruta", "brute_force"}:
            raise ValueError(
                f"El incidente {incident.incident_id} no es de tipo fuerza_bruta o brute_force"
            )

        details = incident.details or {}
        usernames = details.get("usernames")
        if not isinstance(usernames, list):
            username = details.get("username")
            usernames = [username] if isinstance(username, str) else []
        else:
            usernames = [username for username in usernames if isinstance(username, str)]
        attempts = details.get("attempts")
        if not isinstance(attempts, int):
            attempts = details.get("failed_attempts", 1)
        if not isinstance(attempts, int):
            attempts = 1

        return cls(
            incident_id=incident.incident_id,
            source_ip=incident.source_ip,
            target_ip=incident.target_ip,
            service=details.get("service", "unknown"),
            username=usernames[0] if usernames else None,
            usernames=usernames,
            failed_attempts=attempts,
            event_type=incident.event_type,
            severity=incident.severity,
            priority=incident.priority,
            detected_at=incident.created_at,
        )


class ActionResult(BaseModel):
    action_name: str
    target: str

    status: str
    details: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ACTION_STATUSES:
            raise ValueError("Estado de acción fuera de catálogo")
        return v


class BruteForcePlaybookOutput(BaseModel):
    execution_id: str

    incident_id: str

    playbook: str = BRUTE_FORCE_PLAYBOOK

    status: str  # COMPLETED | FAILED | PARTIAL

    actions_taken: list[ActionResult]

    executed_at: datetime

    summary: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in PLAYBOOK_STATUSES:
            raise ValueError("Estado de playbook fuera de catálogo")
        return v


def playbook_status(actions: list[ActionResult]) -> str:
    """
    COMPLETED si todas las acciones tienen éxito, FAILED si ninguna, PARTIAL si hay mezcla.
    """
    successes = sum(action.status == "success" for action in actions)
    if actions and successes == len(actions):
        return "COMPLETED"
    if successes == 0:
        return "FAILED"
    return "PARTIAL"

from datetime import datetime
from typing import Optional
from pydantic import BaseModel



class BruteForcePlaybookInput(BaseModel):
    incident_id: str
    source_ip: str
    target_ip: Optional[str] = None

    service: str = "unknown"
    username: Optional[str] = None

    failed_attempts: int = 1


class ActionResult(BaseModel):
    action_name: str
    target: str

    success: bool
    details: str


class BruteForcePlaybookOutput(BaseModel):
    execution_id: str

    incident_id: str

    status: str  # COMPLETED | FAILED | PARTIAL

    actions_taken: list[ActionResult]

    executed_at: datetime

    summary: str

class BlockIpRequest(BaseModel):
    ip: str
    duration_seconds: Optional[int] = None


class BlockIpResponse(BaseModel):
    status: str

    ip: str

    blocked_at: datetime

    expires_at: Optional[datetime] = None



class BruteForcePlaybookInput(BaseModel):
    incident_id: str
    source_ip: str
    target_ip: Optional[str] = None

    service: str = "unknown"
    username: Optional[str] = None

    failed_attempts: int = 1

    @classmethod
    def from_incident(cls, incident):

        if incident.event_type != "fuerza_bruta":
            raise ValueError(
                f"El incidente {incident.incident_id} no es de tipo fuerza_bruta"
            )

        details = incident.details or {}

        return cls(
            incident_id=incident.incident_id,
            source_ip=incident.source_ip,
            target_ip=incident.target_ip,
            service=details.get("service", "unknown"),
            username=details.get("username"),
            failed_attempts=details.get("failed_attempts", 1),
        )
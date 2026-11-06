from typing import Optional
from pydantic import BaseModel, Field, field_validator
from .schemas import IncidentEntity #normalizacion/schemas.py

class BruteForcePlaybookInput(BaseModel):
    incident_id: str
    source_ip: str
    target_ip: Optional[str] = None
    service: str = "ssh"
    username: Optional[str] = None
    failed_attempts: int = 1

    @classmethod
    def from_incident(cls, incident: IncidentEntity) -> "BruteForcePlaybookInput":
        if incident.event_type != "fuerza_bruta":
            raise ValueError(f"El incidente {incident.incident_id} no es un evento de fuerza_bruta.")
        
        if not incident.source_ip:
            raise ValueError(f"El incidente {incident.incident_id} no tiene IP.")

        details = incident.details or {}
        return cls(
            incident_id=incident.incident_id,
            source_ip=incident.source_ip,
            target_ip=incident.target_ip,
            service=details.get("service", "ssh"),
            username=details.get("username"),
            failed_attempts=details.get("distinct_ports_count", 1)
        )
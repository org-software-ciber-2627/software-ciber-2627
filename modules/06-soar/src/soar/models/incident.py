from pydantic import BaseModel
from typing import Optional

class Incident(BaseModel):
    incident_id: str
    alert_id: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    status: str
    created_at: str
    resolved_at: Optional[str] = None
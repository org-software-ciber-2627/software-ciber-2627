from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class Incident(BaseModel):
    incident_id: str
    alert_id: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    status: str
    created_at: str
    resolved_at: Optional[str] = None
    # Campos opcionales añadidos en la integración del Sprint 2
    priority: Optional[str] = None
    source: Optional[str] = None
    target_ip: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    alert_key: Optional[str] = None

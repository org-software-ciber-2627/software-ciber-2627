import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

# Catálogos propios de la respuesta ejecutada: son independientes de los estados del incidente
RESPONSE_STATUSES = {'pending', 'running', 'success', 'failed', 'skipped'}
RESPONSE_TRIGGERS = {'automatic', 'manual'}


class ExecutedResponse(BaseModel):
    response_id: str = Field(default_factory=lambda: f"RES-{uuid.uuid4().hex[:6].upper()}")
    incident_id: str = Field(..., description="Incidente sobre el que se ejecuta la respuesta (relación 1:N)")
    playbook: str = Field(..., description="Playbook que generó la respuesta, por ejemplo brute_force")
    action: str = Field(..., description="Acción concreta del playbook, por ejemplo notify")
    status: str = Field(default="pending", description="Estado de la respuesta")
    triggered_by: str = Field(default="automatic", description="Origen: automatic o manual")
    executed_at: datetime = Field(..., description="Fecha y hora de inicio de la ejecución (ISO 8601)")
    finished_at: Optional[datetime] = Field(None, description="Fecha y hora de finalización")
    message: Optional[str] = Field(None, description="Mensaje legible sobre el resultado")
    error: Optional[str] = Field(None, description="Error asociado si la acción falla")
    details: Dict[str, Any] = Field(default_factory=dict, description="Datos específicos de la acción")

    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v.lower() not in RESPONSE_STATUSES:
            raise ValueError("Estado de respuesta fuera de catálogo")
        return v.lower()

    @field_validator('triggered_by')
    @classmethod
    def validate_triggered_by(cls, v: str) -> str:
        if v.lower() not in RESPONSE_TRIGGERS:
            raise ValueError("Origen de la respuesta (triggered_by) desconocido")
        return v.lower()

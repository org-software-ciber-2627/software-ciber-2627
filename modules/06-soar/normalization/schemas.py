import uuid
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict

#creamos un DTO para la alerta cruda que se recibe del SIEM, con validaciones de campos y mapeo a un incidente del SOAR

class AlertPayloadDTO(BaseModel):
    model_config = ConfigDict(extra='ignore')

    alert_id: str = Field(..., description="Identificador estable asignado por SIEM")
    event_id: str = Field(..., description="Identificador único del evento original")
    timestamp: datetime = Field(..., description="Fecha y hora de detección en UTC (ISO 8601)")
    source: str = Field(..., description="Productor: ids, honeypot o scanner")
    event_type: str = Field(..., description="Tipo de evento detectado")
    severity: str = Field(..., description="Nivel: low, medium, high o critical")
    title: str = Field(..., description="Resumen legible")
    description: str = Field(..., description="Explicación legible")
    
    source_ip: Optional[str] = Field(None, description="IP origen observada IPv4")
    target_ip: Optional[str] = Field(None, description="Activo de destino IPv4")
    
    details: Dict[str, Any] = Field(..., description="Datos específicos del productor")

    @field_validator('source_ip', 'target_ip')
    @classmethod
    def validate_ipv4(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ipaddress.IPv4Address(v)
            return v
        except ValueError:
            raise ValueError(f"La dirección {v} no es una IPv4 válida.")

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v.lower() not in {'low', 'medium', 'high', 'critical'}:
            raise ValueError("Severidad fuera de catálogo")
        return v.lower()

    @field_validator('source')
    @classmethod
    def validate_source(cls, v: str) -> str:
        if v.lower() not in {'ids', 'honeypot', 'scanner'}:
            raise ValueError("Productor (source) desconocido")
        return v.lower()


class IncidentEntity(AlertPayloadDTO):
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    status: str = Field(default="open") 
    resolved_at: Optional[datetime] = None
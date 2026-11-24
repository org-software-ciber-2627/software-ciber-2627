from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


class BlacklistEntry(BaseModel):
    """
    HU19: IP atacante metida en la lista negra simulada del SOAR (no se bloquea en ningún sistema real).
    """

    ip: str = Field(..., description="IP bloqueada, normalizada con ipaddress")
    incident_id: str = Field(..., description="Incidente que provocó el bloqueo")
    added_at: datetime = Field(..., description="Fecha y hora del bloqueo (UTC)")
    reason: str = Field(..., description="Motivo del bloqueo")

    @field_validator("added_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("added_at must include a UTC timezone")
        return value.astimezone(timezone.utc)

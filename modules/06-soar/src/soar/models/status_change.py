from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, field_validator

from soar.models.incident_status import IncidentStatus


class StatusChange(BaseModel):
    incident_id: str
    from_status: IncidentStatus
    to_status: IncidentStatus
    justification: str
    changed_at: datetime
    resolution_reason: Optional[str] = None

    @field_validator("changed_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("changed_at must include a UTC timezone")
        return value.astimezone(timezone.utc)

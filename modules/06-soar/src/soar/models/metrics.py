from typing import Optional

from pydantic import BaseModel


class IncidentMetrics(BaseModel):
    incident_id: str
    mttd_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None


class MetricsSummary(BaseModel):
    mttd_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    total_incidents: int
    closed_incidents: int

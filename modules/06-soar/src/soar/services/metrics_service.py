from datetime import datetime, timezone
from statistics import fmean
from typing import Optional, Protocol

from soar.models.incident import Incident
from soar.models.metrics import IncidentMetrics, MetricsSummary


class IncidentSource(Protocol):
    def find_all(self) -> list[Incident]:
        ...


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Acepta fechas ISO 8601 con zona horaria."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc)


def _elapsed_seconds(
    start: Optional[str],
    end: Optional[str],
) -> Optional[float]:
    start_dt = _parse_datetime(start)
    end_dt = _parse_datetime(end)

    if start_dt is None or end_dt is None:
        return None

    seconds = (end_dt - start_dt).total_seconds()

    if seconds < 0:
        return None

    return seconds


class MetricsService:
    """Calcula HU16 usando los incidentes del repositorio."""

    def __init__(self, repository: IncidentSource) -> None:
        self._repository = repository

    def calculate_mttd(self, incident: Incident) -> Optional[float]:
        return _elapsed_seconds(
            incident.alert_timestamp,
            incident.created_at,
        )

    def calculate_mttr(self, incident: Incident) -> Optional[float]:
        if incident.status != "closed":
            return None

        return _elapsed_seconds(
            incident.created_at,
            incident.resolved_at,
        )

    def calculate_incident_metrics(
        self,
        incident: Incident,
    ) -> IncidentMetrics:
        return IncidentMetrics(
            incident_id=incident.incident_id,
            mttd_seconds=self.calculate_mttd(incident),
            mttr_seconds=self.calculate_mttr(incident),
        )

    def calculate_metrics(self) -> MetricsSummary:
        incidents = self._repository.find_all()

        mttd_values = []
        mttr_values = []

        for incident in incidents:
            mttd = self.calculate_mttd(incident)
            mttr = self.calculate_mttr(incident)

            if mttd is not None:
                mttd_values.append(mttd)

            if mttr is not None:
                mttr_values.append(mttr)

        return MetricsSummary(
            mttd_seconds=(
                fmean(mttd_values) if mttd_values else None
            ),
            mttr_seconds=(
                fmean(mttr_values) if mttr_values else None
            ),
            total_incidents=len(incidents),
            closed_incidents=sum(
                incident.status == "closed"
                for incident in incidents
            ),
        )

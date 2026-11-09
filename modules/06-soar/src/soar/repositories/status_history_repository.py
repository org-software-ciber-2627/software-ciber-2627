from soar.models.status_change import StatusChange


class StatusHistoryRepository:
    def __init__(self) -> None:
        self._changes: list[StatusChange] = []

    def add(self, change: StatusChange) -> None:
        self._changes.append(change)

    def get_by_incident(self, incident_id: str) -> list[StatusChange]:
        return sorted(
            (change for change in self._changes if change.incident_id == incident_id),
            key=lambda change: change.changed_at,
        )

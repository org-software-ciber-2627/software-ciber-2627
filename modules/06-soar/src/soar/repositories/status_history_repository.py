from soar.models.status_change import StatusChange
from soar.repositories.sqlite import connect


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


class SqliteStatusHistoryRepository:
    """
    Misma interfaz que StatusHistoryRepository, persistida en la tabla status_history.
    """

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        with connect(database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    change_json TEXT NOT NULL
                )
                """
            )

    def add(self, change: StatusChange) -> None:
        with connect(self._database_path) as connection:
            connection.execute(
                "INSERT INTO status_history (incident_id, change_json) VALUES (?, ?)",
                (change.incident_id, change.model_dump_json()),
            )

    def get_by_incident(self, incident_id: str) -> list[StatusChange]:
        with connect(self._database_path) as connection:
            rows = connection.execute(
                "SELECT change_json FROM status_history WHERE incident_id = ? ORDER BY id", (incident_id,)
            ).fetchall()
        changes = [StatusChange.model_validate_json(row["change_json"]) for row in rows]
        return sorted(changes, key=lambda change: change.changed_at)

from typing import Iterable, Optional

from soar.models.incident import Incident
from soar.repositories.sqlite import connect


class IncidentRepository:
    def __init__(self, incidents: Iterable[Incident] = ()) -> None:
        self._incidents = list(incidents)

    def find_all(self) -> list[Incident]:
        return list(self._incidents)


class SqliteIncidentRepository:
    """
    Guarda el Incident normalizado en la tabla soar_incidents.
    """

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        with connect(database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS soar_incidents (
                    incident_id TEXT PRIMARY KEY,
                    alert_key TEXT UNIQUE,
                    incident_json TEXT NOT NULL
                )
                """
            )

    def save(self, incident: Incident) -> Incident:
        """Inserta el incidente o lo sustituye si ya existe."""
        with connect(self._database_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO soar_incidents (incident_id, alert_key, incident_json) VALUES (?, ?, ?)",
                (incident.incident_id, incident.alert_key, incident.model_dump_json()),
            )
        return incident

    def find_all(self) -> list[Incident]:
        return self._select("SELECT incident_json FROM soar_incidents ORDER BY rowid", ())

    def find_by_id(self, incident_id: str) -> Optional[Incident]:
        found = self._select("SELECT incident_json FROM soar_incidents WHERE incident_id = ?", (incident_id,))
        return found[0] if found else None

    def find_by_alert_key(self, alert_key: str) -> Optional[Incident]:
        found = self._select("SELECT incident_json FROM soar_incidents WHERE alert_key = ?", (alert_key,))
        return found[0] if found else None

    def _select(self, query: str, params: tuple) -> list[Incident]:
        with connect(self._database_path) as connection:
            rows = connection.execute(query, params).fetchall()
        return [Incident.model_validate_json(row["incident_json"]) for row in rows]

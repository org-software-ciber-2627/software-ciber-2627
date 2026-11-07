from typing import Iterable

from soar.models.executed_response import ExecutedResponse
from soar.repositories.sqlite import connect


class ResponseRepository:
    def __init__(self, responses: Iterable[ExecutedResponse] = ()) -> None:
        self._responses = list(responses)

    def save(self, response: ExecutedResponse) -> ExecutedResponse:
        self._responses.append(response)
        return response

    def find_all(self) -> list[ExecutedResponse]:
        return list(self._responses)

    def find_by_incident_id(self, incident_id: str) -> list[ExecutedResponse]:
        return [response for response in self._responses if response.incident_id == incident_id]


class SqliteResponseRepository:
    """
    Misma interfaz que ResponseRepository, persistida en la tabla executed_responses.
    """

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        with connect(database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS executed_responses (
                    response_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    response_json TEXT NOT NULL
                )
                """
            )

    def save(self, response: ExecutedResponse) -> ExecutedResponse:
        with connect(self._database_path) as connection:
            connection.execute(
                "INSERT INTO executed_responses (response_id, incident_id, response_json) VALUES (?, ?, ?)",
                (response.response_id, response.incident_id, response.model_dump_json()),
            )
        return response

    def find_all(self) -> list[ExecutedResponse]:
        return self._select("SELECT response_json FROM executed_responses ORDER BY rowid", ())

    def find_by_incident_id(self, incident_id: str) -> list[ExecutedResponse]:
        return self._select(
            "SELECT response_json FROM executed_responses WHERE incident_id = ? ORDER BY rowid", (incident_id,)
        )

    def _select(self, query: str, params: tuple) -> list[ExecutedResponse]:
        with connect(self._database_path) as connection:
            rows = connection.execute(query, params).fetchall()
        return [ExecutedResponse.model_validate_json(row["response_json"]) for row in rows]

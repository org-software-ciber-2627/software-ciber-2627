from typing import Iterable

from soar.models.executed_response import ExecutedResponse


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

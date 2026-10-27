from soar.models.executed_response import ExecutedResponse
from soar.repositories.response_repository import ResponseRepository


class ResponseService:
    # Solo registra y consulta resultados; la ejecución del playbook queda fuera de este servicio
    def __init__(self, repository: ResponseRepository) -> None:
        self._repository = repository

    def register_response(self, response: ExecutedResponse) -> ExecutedResponse:
        return self._repository.save(response)

    def list_responses(self) -> list[ExecutedResponse]:
        return self._repository.find_all()

    def list_responses_by_incident(self, incident_id: str) -> list[ExecutedResponse]:
        return self._repository.find_by_incident_id(incident_id)

from soar.models.incident import Incident
from soar.repositories.incident_repository import IncidentRepository


class IncidentService:
    def __init__(self, repository: IncidentRepository) -> None:
        self._repository = repository

    def list_incidents(self) -> list[Incident]:
        return self._repository.find_all()

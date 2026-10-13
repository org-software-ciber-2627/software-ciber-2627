from typing import Iterable

from soar.models.incident import Incident


class IncidentRepository:
    def __init__(self, incidents: Iterable[Incident] = ()) -> None:
        self._incidents = list(incidents)

    def find_all(self) -> list[Incident]:
        return list(self._incidents)

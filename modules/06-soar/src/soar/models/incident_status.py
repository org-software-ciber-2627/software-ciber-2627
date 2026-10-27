from enum import Enum


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    CLOSED = "closed"


ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {IncidentStatus.IN_PROGRESS, IncidentStatus.CLOSED}
    ),
    IncidentStatus.IN_PROGRESS: frozenset(
        {IncidentStatus.CONTAINED, IncidentStatus.CLOSED}
    ),
    IncidentStatus.CONTAINED: frozenset(
        {IncidentStatus.IN_PROGRESS, IncidentStatus.CLOSED}
    ),
    IncidentStatus.CLOSED: frozenset(),
}


def is_transition_allowed(
    current: IncidentStatus, target: IncidentStatus
) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())

from enum import Enum


class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Matriz o reglas base de prioridad
# Se calcula combinando severidad reportada y tipo de evento
SEVERITY_MAPPING = {
    "critical": PriorityLevel.CRITICAL,
    "high": PriorityLevel.HIGH,
    "medium": PriorityLevel.MEDIUM,
    "low": PriorityLevel.LOW,
}

CRITICAL_EVENT_TYPES = {
    "ransomware_detected",
    "data_exfiltration",
    "privilege_escalation"
}
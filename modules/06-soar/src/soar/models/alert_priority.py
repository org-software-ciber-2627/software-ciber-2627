from enum import Enum
from typing import Dict, Set


class PriorityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Mapeo base por severidad recibida
SEVERITY_MAPPING: Dict[str, PriorityLevel] = {
    "low": PriorityLevel.LOW,
    "medium": PriorityLevel.MEDIUM,
    "high": PriorityLevel.HIGH,
    "critical": PriorityLevel.CRITICAL,
}

# Eventos que escalan automáticamente a CRITICAL
CRITICAL_EVENT_TYPES: Set[str] = {
    "ransomware_detected",
    "data_exfiltration",
}
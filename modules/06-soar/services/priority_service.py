from typing import Dict, Any
from ..models.priority import PriorityLevel, SEVERITY_MAPPING, CRITICAL_EVENT_TYPES


def calculate_priority(incident_data: Dict[str, Any]) -> PriorityLevel:
    """
    Calcula el nivel de prioridad según severidad y tipo de evento.
    """
    severity = str(incident_data.get("severity", "")).lower()
    event_type = str(incident_data.get("event_type", "")).lower()

    # Regla 1: Tipos de eventos críticos elevan la prioridad inmediatamente
    if event_type in CRITICAL_EVENT_TYPES or severity == "critical":
        return PriorityLevel.CRITICAL

    # Regla 2: Mapeo directo por severidad conocida
    if severity in SEVERITY_MAPPING:
        return SEVERITY_MAPPING[severity]

    # Regla 3: Si la severidad no viene definida o es desconocida, asigna LOW por defecto
    return PriorityLevel.LOW


def prioritize_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Asigna el campo 'priority' al incidente sin modificar otros campos del flujo.
    """
    updated_incident = incident.copy()
    updated_incident["priority"] = calculate_priority(updated_incident).value
    return updated_incident
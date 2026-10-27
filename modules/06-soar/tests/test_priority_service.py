import pytest
# Importamos la lógica desarrollada en HU5.2 y los modelos de HU5.1
from ..services.priority_service import prioritize_incident, calculate_priority
from ..models.priority import PriorityLevel


def test_critical_by_severity():
    """
    CASO 1: Prioridad crítica determinada por el campo 'severity'.
    
    Verifica que si la severidad recibida desde el SIEM es explícitamente 'critical',
    el incidente recibe la prioridad máxima ('critical'), independientemente de que
    el tipo de evento sea genérico (ej. 'port_scan').
    """
    incident = {"id": "INC-001", "severity": "critical", "event_type": "port_scan"}
    res = prioritize_incident(incident)
    # Comprueba que el valor asignado sea 'critical'
    assert res["priority"] == PriorityLevel.CRITICAL.value


def test_critical_by_event_type():
    """
    CASO 2: Prioridad crítica forzada por tipo de evento peligroso.
    
    Verifica que eventos especialmente graves (como 'ransomware_detected') escalen
    automáticamente a prioridad 'critical', incluso si la severidad reportada
    inicialmente era menor (en este caso, 'medium').
    """
    incident = {"id": "INC-002", "severity": "medium", "event_type": "ransomware_detected"}
    res = prioritize_incident(incident)
    # Debe ser 'critical' por la regla de CRITICAL_EVENT_TYPES
    assert res["priority"] == PriorityLevel.CRITICAL.value


def test_high_medium_low_mapping():
    """
    CASO 3: Mapeo directo y estándar de niveles ordinarios.
    
    Prueba directamente la función de cálculo base ('calculate_priority') para verificar
    que las severidades estándar ('high', 'medium', 'low') se traduzcan de manera
    directa a sus enums equivalentes (HIGH, MEDIUM, LOW) sin alteraciones.
    """
    assert calculate_priority({"severity": "high", "event_type": "brute_force"}) == PriorityLevel.HIGH
    assert calculate_priority({"severity": "medium", "event_type": "unknown"}) == PriorityLevel.MEDIUM
    assert calculate_priority({"severity": "low", "event_type": "info"}) == PriorityLevel.LOW


def test_unknown_or_missing_severity_defaults_to_low():
    """
    CASO 4: Resiliencia ante datos incompletos o desconocidos.
    
    Verifica que el servicio no falle (no lance excepciones no controladas) si llega
    un incidente sin el campo 'severity' o con un valor desconocido. Por diseño seguro,
    debe asignar el nivel por defecto más bajo ('low').
    """
    incident = {"id": "INC-003", "event_type": "unknown_event"}
    res = prioritize_incident(incident)
    # Comprueba que ante la ausencia de severidad se aplique el valor por defecto 'low'
    assert res["priority"] == PriorityLevel.LOW.value


def test_incident_fields_are_preserved():
    """
    CASO 5: Integridad e inmutabilidad de los datos originales.
    
    Verifica el principio de no alteración: la función 'prioritize_incident' debe
    añadir el nuevo campo 'priority' sin borrar, sobreescribir ni corromper los datos
    que ya venían del SIEM o del evento original ('id', 'source_ip', etc.).
    """
    incident = {"id": "INC-004", "source_ip": "192.168.1.50", "severity": "high"}
    res = prioritize_incident(incident)
    # Se comprueba que los campos originales sigan exactamente igual
    assert res["id"] == "INC-004"
    assert res["source_ip"] == "192.168.1.50"
    # Y que además se haya incorporado la nueva prioridad calculada
    assert res["priority"] == PriorityLevel.HIGH.value
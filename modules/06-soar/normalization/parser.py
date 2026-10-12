from pydantic import ValidationError

from .schemas import AlertPayloadDTO, IncidentEntity

def parse_and_normalize_alert(raw_alert_dict: dict) -> IncidentEntity:
    """
    Deserializa un diccionario de alerta crudo extraído del array del SIEM,
    lo valida contra el contrato y lo mapea a un incidente del SOAR.
    """
    try:
        validated_dto = AlertPayloadDTO(**raw_alert_dict)
        incident = IncidentEntity(**validated_dto.model_dump())
        return incident
        
    except ValidationError as e:
        raise ValueError(f"Alerta descartada por incumplir contrato: {e.errors()}")
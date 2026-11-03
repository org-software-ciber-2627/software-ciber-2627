import uuid
from datetime import datetime, timezone

from pydantic import ValidationError

from soar.models.incident import Incident
from .schemas import AlertPayloadDTO

def parse_and_normalize_alert(raw_alert_dict: dict) -> Incident:
    """
    Deserializa un diccionario de alerta crudo extraído del array del SIEM,
    lo valida contra el contrato y lo mapea a un incidente del SOAR.
    """
    try:
        validated_dto = AlertPayloadDTO(**raw_alert_dict)
    except ValidationError as e:
        raise ValueError(f"Alerta descartada por incumplir contrato: {e.errors()}")

    return Incident(
        incident_id=f"INC-{uuid.uuid4().hex[:6].upper()}",
        alert_id=validated_dto.alert_id,
        event_type=validated_dto.event_type,
        severity=validated_dto.severity,
        source_ip=validated_dto.source_ip,
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        source=validated_dto.source,
        target_ip=validated_dto.target_ip,
        title=validated_dto.title,
        description=validated_dto.description,
        details=validated_dto.details,
    )

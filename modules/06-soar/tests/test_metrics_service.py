from datetime import datetime

from soar.models.incident import Incident
from soar.normalization.parser import parse_and_normalize_alert
from soar.repositories.incident_repository import (
    IncidentRepository,
    SqliteIncidentRepository,
)
from soar.services.metrics_service import MetricsService


def make_incident(**changes):
    data = {
        "incident_id": "INC-1",
        "alert_id": "ALT-1",
        "event_type": "fuerza_bruta",
        "severity": "high",
        "status": "closed",
        "created_at": "2026-11-25T12:00:10Z",
        "alert_timestamp": "2026-11-25T12:00:00Z",
        "resolved_at": "2026-11-25T12:01:40Z",
    }
    data.update(changes)
    return Incident(**data)


def service_with(*incidents):
    return MetricsService(IncidentRepository(incidents))


def test_mttd_individual():
    incident = make_incident()
    assert service_with(incident).calculate_mttd(incident) == 10.0


def test_mttr_individual():
    incident = make_incident()
    assert service_with(incident).calculate_mttr(incident) == 90.0


def test_incidente_abierto_no_tiene_mttr():
    incident = make_incident(status="open", resolved_at=None)
    assert service_with(incident).calculate_mttr(incident) is None


def test_incidente_contenido_no_tiene_mttr():
    incident = make_incident(status="contained")
    assert service_with(incident).calculate_mttr(incident) is None


def test_sin_timestamp_no_hay_mttd():
    incident = make_incident(alert_timestamp=None)
    assert service_with(incident).calculate_mttd(incident) is None


def test_sin_resolved_at_no_hay_mttr():
    incident = make_incident(resolved_at=None)
    assert service_with(incident).calculate_mttr(incident) is None


def test_fecha_invalida_devuelve_none():
    incident = make_incident(created_at="fecha-invalida")
    service = service_with(incident)
    assert service.calculate_mttd(incident) is None
    assert service.calculate_mttr(incident) is None


def test_fecha_sin_zona_horaria_devuelve_none():
    incident = make_incident(
        alert_timestamp="2026-11-25T12:00:00"
    )
    assert service_with(incident).calculate_mttd(incident) is None


def test_duracion_negativa_devuelve_none():
    incident = make_incident(
        alert_timestamp="2026-11-25T12:00:30Z",
        resolved_at="2026-11-25T12:00:05Z",
    )
    service = service_with(incident)
    assert service.calculate_mttd(incident) is None
    assert service.calculate_mttr(incident) is None


def test_zonas_horarias():
    incident = make_incident(
        alert_timestamp="2026-11-25T14:00:00+02:00"
    )
    assert service_with(incident).calculate_mttd(incident) == 10.0


def test_sin_incidentes():
    summary = service_with().calculate_metrics()
    assert summary.mttd_seconds is None
    assert summary.mttr_seconds is None
    assert summary.total_incidents == 0
    assert summary.closed_incidents == 0


def test_medias_globales():
    first = make_incident()
    second = make_incident(
        incident_id="INC-2",
        status="open",
        created_at="2026-11-25T12:00:20Z",
        resolved_at=None,
    )
    third = make_incident(
        incident_id="INC-3",
        alert_timestamp=None,
        resolved_at="2026-11-25T12:00:40Z",
    )

    summary = service_with(first, second, third).calculate_metrics()

    assert summary.total_incidents == 3
    assert summary.closed_incidents == 2
    assert summary.mttd_seconds == 15.0
    assert summary.mttr_seconds == 60.0


def test_cero_segundos_es_valido():
    incident = make_incident(
        alert_timestamp="2026-11-25T12:00:10Z",
        resolved_at="2026-11-25T12:00:10Z",
    )
    summary = service_with(incident).calculate_metrics()
    assert summary.mttd_seconds == 0.0
    assert summary.mttr_seconds == 0.0


def test_modelo_antiguo_sin_timestamp():
    data = make_incident().model_dump()
    data.pop("alert_timestamp")
    legacy_incident = Incident.model_validate(data)

    assert service_with(legacy_incident).calculate_mttd(
        legacy_incident
    ) is None


def test_persistencia_sqlite(tmp_path):
    repository = SqliteIncidentRepository(
        str(tmp_path / "metrics_test.db")
    )
    incident = make_incident()
    repository.save(incident)

    loaded = repository.find_all()

    assert len(loaded) == 1
    assert loaded[0].alert_timestamp == incident.alert_timestamp

    summary = MetricsService(repository).calculate_metrics()
    assert summary.mttd_seconds == 10.0
    assert summary.mttr_seconds == 90.0


def test_normalizacion_conserva_timestamp():
    alert = {
        "alert_id": "ALT-1",
        "event_id": "EVT-1",
        "timestamp": "2026-11-25T12:00:00Z",
        "source": "honeypot",
        "event_type": "fuerza_bruta",
        "severity": "high",
        "title": "Ataque de fuerza bruta",
        "description": "Múltiples intentos de acceso",
        "source_ip": "192.0.2.10",
        "target_ip": "192.0.2.20",
        "details": {},
    }

    incident = parse_and_normalize_alert(alert)

    assert datetime.fromisoformat(
        incident.alert_timestamp
    ) == datetime.fromisoformat(
        "2026-11-25T12:00:00+00:00"
    )


def test_resultado_por_incidente():
    incident = make_incident()
    result = service_with(incident).calculate_incident_metrics(
        incident
    )

    assert result.incident_id == "INC-1"
    assert result.mttd_seconds == 10.0
    assert result.mttr_seconds == 90.0


def test_no_modifica_incidente():
    incident = make_incident()
    original = incident.model_dump()

    service_with(incident).calculate_incident_metrics(incident)

    assert incident.model_dump() == original

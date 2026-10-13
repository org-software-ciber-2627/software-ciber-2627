import pytest
#clase para crear pruebas unitarias para la función parse_and_normalize_alert, de esta forma comprobamos que la normalización de alertas funciona correctamente y que se rechazan las alertas inválidas
from normalization.parser import parse_and_normalize_alert

def test_parse_valid_honeypot_alert():
    raw_data = {
      "alert_id": "SIEM-ALERT-EJEMPLO-002",
      "event_id": "HP-981839239323",
      "timestamp": "2026-09-22T18:30:15Z",
      "source": "honeypot",
      "event_type": "fuerza_bruta",
      "severity": "medium",
      "title": "Intento de fuerza bruta en el honeypot",
      "description": "El honeypot ha registrado un evento...",
      "source_ip": "192.168.1.50",
      "target_ip": None,
      "details": {"username": "root"}
    }
    
    incident = parse_and_normalize_alert(raw_data)
    assert incident.alert_id == "SIEM-ALERT-EJEMPLO-002"
    assert incident.target_ip is None
    assert incident.status == "open"
    assert incident.incident_id.startswith("INC-")

def test_parse_valid_scanner_alert():
    raw_data = {
      "alert_id": "SIEM-ALERT-EJEMPLO-003",
      "event_id": "b52ee782-265f-4ec7-a719",
      "timestamp": "2026-09-29T10:30:00Z",
      "source": "scanner",
      "event_type": "vulnerability_detected",
      "severity": "medium",
      "title": "Cabecera de seguridad ausente",
      "description": "El servicio HTTP no devuelve cabeceras.",
      "source_ip": None,
      "target_ip": "192.168.56.10",
      "details": {"tool": "nmap"}
    }
    
    incident = parse_and_normalize_alert(raw_data)
    assert incident.source_ip is None
    assert incident.source == "scanner"

def test_invalid_ipv4_rejected():
    raw_data = {
        "alert_id": "SIEM-001", "event_id": "EV-01", "timestamp": "2026-09-22T18:30:15Z",
        "source": "ids", "event_type": "scan", "severity": "low",
        "title": "T", "description": "D", "details": {},
        "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "target_ip": "999.999.999.999"
    }
    with pytest.raises(ValueError, match="no es una IPv4 válida"):
        parse_and_normalize_alert(raw_data)

def test_invalid_source_rejected():
    raw_data = {
        "alert_id": "SIEM-001", "event_id": "EV-01", "timestamp": "2026-09-22T18:30:15Z",
        "source": "firewall_externo",
        "event_type": "drop", "severity": "low", "title": "T", "description": "D",
        "source_ip": "10.0.0.1", "target_ip": None, "details": {}
    }
    with pytest.raises(ValueError, match="Productor \\(source\\) desconocido"):
        parse_and_normalize_alert(raw_data)

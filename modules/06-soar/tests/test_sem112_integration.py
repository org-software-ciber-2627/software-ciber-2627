import json
import hashlib
from pathlib import Path
from unittest.mock import patch

import app
import pytest
from soar.models.playbook import BruteForcePlaybookInput
from soar.normalization.parser import parse_and_normalize_alert
from soar.services.automation_detector import evaluate_automation


P004_EVENT = {
    "event_id": "IDS-P004-122.5.240.60-20260420T135010Z",
    "timestamp": "2026-04-20T13:51:02Z",
    "source": "ids",
    "event_type": "brute_force",
    "severity": "medium",
    "title": "Posible ataque de fuerza bruta",
    "description": (
        "La IP 122.5.240.60 ha realizado 12 intentos fallidos de login "
        "contra 2 usuario(s) entre 2026-04-20T13:50:10Z y 2026-04-20T13:51:02Z."
    ),
    "details": {
        "rule_id": "P004",
        "source_ip": "122.5.240.60",
        "service": "sshd",
        "attempts": 12,
        "usernames": ["root", "admin"],
        "window_seconds": 60,
        "first_attempt": "2026-04-20T13:50:10Z",
        "last_attempt": "2026-04-20T13:51:02Z",
        "login_success": False,
    },
}


def convert_event(event):
    source = event["source"]
    details = event["details"]
    source_ip = details.get("source_ip") if source in {"ids", "honeypot"} else None
    target_ip = details.get("target_ip") if source == "ids" else None
    digest = bytearray(
        hashlib.md5(f"{source}:{event['event_id']}".encode("utf-8")).digest()
    )
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    alert_id = "SIEM-ALERT-" + "-".join(
        (
            digest[:4].hex(),
            digest[4:6].hex(),
            digest[6:8].hex(),
            digest[8:10].hex(),
            digest[10:].hex(),
        )
    )
    return {
        "alert_id": alert_id,
        **event,
        "source_ip": source_ip,
        "target_ip": target_ip,
    }


def test_real_ids_alert_from_sem112_is_automatable_and_preserves_data():
    incident = parse_and_normalize_alert(convert_event(P004_EVENT))

    decision = evaluate_automation(incident)
    playbook_input = BruteForcePlaybookInput.from_incident(incident)

    assert decision.automatable is True
    assert decision.playbook == "brute_force"
    assert playbook_input.failed_attempts == 12
    assert playbook_input.usernames == ["root", "admin"]


def test_sem112_honeypot_and_pentesting_examples_have_expected_decisions():
    honeypot = json.loads(
        (
            Path(__file__).parents[2]
            / "05-siem"
            / "contract"
            / "examples"
            / "grupo_3_honeypot_actual.json"
        ).read_text(encoding="utf-8")
    )
    pentesting = {
        "alert_id": "SIEM-ALERT-PENTESTING",
        "event_id": "pt-zap-0001",
        "timestamp": "2026-11-04T12:00:00Z",
        "source": "pentesting",
        "event_type": "vulnerability_detected",
        "severity": "medium",
        "title": "Cross-Domain Misconfiguration",
        "description": "CORS misconfiguration permits cross-domain read requests from arbitrary origins.",
        "details": {"tool": "OWASP ZAP", "target": "http://juice-shop:3000", "instances": 15},
    }

    honeypot_incident = parse_and_normalize_alert(convert_event(honeypot))

    assert evaluate_automation(honeypot_incident).automatable is True
    assert BruteForcePlaybookInput.from_incident(honeypot_incident).usernames == ["admin"]
    with pytest.raises(ValueError):
        parse_and_normalize_alert(pentesting)


def test_sem112_poll_counts_ids_honeypot_and_pentesting(tmp_path, monkeypatch):
    alerts = [
        convert_event(P004_EVENT),
        json.loads(
            (Path(__file__).parents[2] / "05-siem" / "mocks" / "alerts.json").read_text(
                encoding="utf-8"
            )
        )["alerts"][1],
        {
            "alert_id": "SIEM-ALERT-PENTESTING",
            "event_id": "pt-zap-0001",
            "timestamp": "2026-11-04T12:00:00Z",
            "source": "pentesting",
            "event_type": "vulnerability_detected",
            "severity": "medium",
            "title": "Cross-Domain Misconfiguration",
            "description": "CORS misconfiguration permits cross-domain read requests from arbitrary origins.",
            "details": {"tool": "OWASP ZAP", "target": "http://juice-shop:3000", "instances": 15},
        },
    ]
    monkeypatch.setattr(app, "DATABASE_PATH", str(tmp_path / "sem112-test.db"))
    with patch.object(app, "fetch_alerts", return_value=alerts):
        result = app.poll_siem()

    assert result == {"received": 3, "created": 2, "ignored": 0, "rejected": 1, "automated": 2}

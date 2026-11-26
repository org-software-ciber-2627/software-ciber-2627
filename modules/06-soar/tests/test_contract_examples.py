"""
Ejemplos de contract/api-examples/ para el grupo 7, generados con la API real del SOAR.

- Sin variables de entorno: comprueba que cada ejemplo tiene exactamente las mismas claves,
  también las anidadas, que lo que devuelve hoy la API.
- Con SOAR_WRITE_EXAMPLES=1: vuelve a generar los ficheros (python -m pytest tests/test_contract_examples.py).

Escenario: alerta de fuerza bruta del honeypot con una IP bloqueable y sin GROUP7_NOTIFY_URL,
como en la demo. El incidente termina en contained.
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app

# No es contract/examples/: el job event-schema del CI valida ahí solo eventos del SIEM
EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "contract" / "api-examples"
MOCK_ALERTS = json.loads(
    (Path(__file__).resolve().parent.parent / "mocks" / "alertas_mock.json").read_text(encoding="utf-8")
)["alerts"]

# Fecha base de los ejemplos: la detección del honeypot es 2 s anterior
EXAMPLE_START = datetime(2026, 11, 26, 10, 0, 0, tzinfo=timezone.utc)
ALERT_TIMESTAMP = "2026-11-26T09:59:58Z"
EXAMPLE_INCIDENT_ID = "INC-4F9A2C"
EXAMPLE_RESPONSE_IDS = ["RES-1B07E4", "RES-20A761"]
EXAMPLE_EXECUTION_ID = "4f31ca91-ab2b-416f-b420-1711ad4b6a11"
DATE_KEYS = {"first_seen", "created_at", "resolved_at", "executed_at", "finished_at", "changed_at"}


def brute_force_alert() -> dict:
    alert = json.loads(json.dumps(MOCK_ALERTS[1]))
    alert["timestamp"] = ALERT_TIMESTAMP
    return alert


def get_json(base_url: str, path: str):
    with urllib.request.urlopen(f"{base_url}{path}", timeout=5) as response:
        assert response.status == 200
        return json.loads(response.read().decode("utf-8"))


def generate_api_responses(tmp_path: Path) -> dict[str, object]:
    """Ejecuta el flujo real (POST /poll interno) y devuelve las tres respuestas de la API."""
    environment = {"GROUP7_NOTIFY_URL": "", "BLACKLIST_EXCLUDED_NETWORKS": ""}
    with patch.dict(os.environ, environment), patch.object(app, "DATABASE_PATH", str(tmp_path / "soar.db")):
        with patch.object(app, "fetch_alerts", return_value=[brute_force_alert()]):
            app.poll_siem()
        server = ThreadingHTTPServer(("127.0.0.1", 0), app.SoarHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            incidents = get_json(base_url, "/incidents")
            incident_id = incidents[0]["incident_id"]
            history = get_json(base_url, f"/incidents/{incident_id}/history")
            responses = get_json(base_url, f"/incidents/{incident_id}/responses")
        finally:
            server.shutdown()
            server.server_close()
    return {"incidents.json": incidents, "history.json": history, "responses.json": responses}


def parse_date(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def collect_dates(data, found: list[str]) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key in DATE_KEYS and isinstance(value, str):
                found.append(value)
            else:
                collect_dates(value, found)
    elif isinstance(data, list):
        for item in data:
            collect_dates(item, found)


def stabilize(api_responses: dict[str, object]) -> dict[str, object]:
    """
    Sustituye los valores que cambian en cada ejecución por valores de ejemplo fijos:
    incident_id, response_id, execution_id y fechas. Las fechas se desplazan a EXAMPLE_START
    conservando su orden, sus diferencias (en milisegundos) y su formato (Z o +00:00).
    """
    text = json.dumps(api_responses)
    real_incident_ids = sorted(set(re.findall(r"INC-[0-9A-F]{6}", text)))
    assert len(real_incident_ids) == 1, real_incident_ids
    text = text.replace(real_incident_ids[0], EXAMPLE_INCIDENT_ID)

    real_response_ids = list(dict.fromkeys(re.findall(r"RES-[0-9A-F]{6}", text)))
    assert len(real_response_ids) == len(EXAMPLE_RESPONSE_IDS), real_response_ids
    for real, example in zip(real_response_ids, EXAMPLE_RESPONSE_IDS):
        text = text.replace(real, example)

    real_execution_ids = set(re.findall(r'"execution_id": "([0-9a-f-]{36})"', text))
    assert len(real_execution_ids) == 1, real_execution_ids
    text = text.replace(real_execution_ids.pop(), EXAMPLE_EXECUTION_ID)

    dates: list[str] = []
    collect_dates(api_responses, dates)
    earliest = min(parse_date(value) for value in dates)
    for value in sorted(set(dates), key=len, reverse=True):
        offset = parse_date(value) - earliest
        shifted = EXAMPLE_START + timedelta(milliseconds=round(offset.total_seconds() * 1000))
        replacement = shifted.isoformat().replace("+00:00", "Z") if value.endswith("Z") else shifted.isoformat()
        if shifted.microsecond == 0:
            replacement = replacement.replace("Z", ".000000Z").replace("+00:00", ".000000+00:00")
        text = text.replace(f'"{value}"', f'"{replacement}"')
    return json.loads(text)


def key_shape(data):
    """Estructura de claves: dicts → {clave: forma}, listas → lista de formas, valores → None."""
    if isinstance(data, dict):
        return {key: key_shape(value) for key, value in data.items()}
    if isinstance(data, list):
        return [key_shape(item) for item in data]
    return None


def test_examples_have_the_same_keys_as_the_real_api(tmp_path: Path) -> None:
    api_responses = generate_api_responses(tmp_path)
    if os.getenv("SOAR_WRITE_EXAMPLES") == "1":
        EXAMPLES_DIR.mkdir(exist_ok=True)
        for name, data in stabilize(api_responses).items():
            (EXAMPLES_DIR / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for name, data in api_responses.items():
        example = json.loads((EXAMPLES_DIR / name).read_text(encoding="utf-8"))
        assert key_shape(example) == key_shape(data), f"{name} no tiene las mismas claves que la API"


def test_examples_show_the_contained_demo_incident() -> None:
    incidents = json.loads((EXAMPLES_DIR / "incidents.json").read_text(encoding="utf-8"))
    history = json.loads((EXAMPLES_DIR / "history.json").read_text(encoding="utf-8"))
    responses = json.loads((EXAMPLES_DIR / "responses.json").read_text(encoding="utf-8"))

    incident = incidents[0]
    assert incident["status"] == "contained"
    assert incident["alert"]["details"]["credential"] == "***"
    assert incident["alert"]["details"]["username"] == "***"
    assert [(r["action"], r["status"]) for r in responses] == [("block_ip", "success"), ("notify", "skipped")]
    assert incident["responses"] == responses
    assert [(c["from_status"], c["to_status"], c["changed_by"]) for c in history] == [
        ("open", "in_progress", "soar-automation"),
        ("in_progress", "contained", "soar-automation"),
    ]

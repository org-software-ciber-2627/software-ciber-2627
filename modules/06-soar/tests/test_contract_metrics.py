from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

import app as soar_app
from soar.models.incident import Incident
from soar.repositories.incident_repository import SqliteIncidentRepository
from test_contract_incidents import _start_contract_server


EXPECTED_KEYS = {
    "mttd_seconds",
    "mttr_seconds",
    "total_incidents",
    "closed_incidents",
}


def _assert_metrics_contract(payload: dict[str, object]) -> None:
    assert set(payload) == EXPECTED_KEYS
    for key in ("mttd_seconds", "mttr_seconds"):
        assert payload[key] is None or type(payload[key]) in (float, int)
    for key in ("total_incidents", "closed_incidents"):
        assert type(payload[key]) is int
        assert payload[key] >= 0
    assert payload["closed_incidents"] <= payload["total_incidents"]


def test_contract_get_metrics_matches_documented_examples(tmp_path, monkeypatch) -> None:
    """Test de contrato proveedor (SOAR) → consumidor (Dashboard G7)."""
    database_path = tmp_path / "contract_metrics.db"
    server, base_url = _start_contract_server(database_path, monkeypatch)
    try:
        responses = []
        with urllib.request.urlopen(f"{base_url}/metrics") as response:
            assert response.status == 200
            assert response.headers.get("Content-Type") == "application/json"
            empty_payload = json.loads(response.read().decode("utf-8"))
        _assert_metrics_contract(empty_payload)
        responses.append(empty_payload)

        SqliteIncidentRepository(str(database_path)).save(
            Incident(
                incident_id="INC-CONTRACT-METRICS",
                alert_id="AL-CONTRACT-METRICS",
                event_type="brute_force",
                severity="high",
                status="open",
                created_at="2026-11-26T10:00:00+00:00",
            )
        )
        with urllib.request.urlopen(f"{base_url}/metrics") as response:
            assert response.status == 200
            assert response.headers.get("Content-Type") == "application/json"
            populated_payload = json.loads(response.read().decode("utf-8"))
        _assert_metrics_contract(populated_payload)
        responses.append(populated_payload)

        contract_path = Path(__file__).parents[1] / "contract" / "metrics.md"
        contract = contract_path.read_text(encoding="utf-8")
        http_section = contract.split("## Exposición HTTP (HU18)", 1)[1]
        http_section = re.split(r"\n## ", http_section, maxsplit=1)[0]
        examples = [
            json.loads(block)
            for block in re.findall(r"```json\s*(.*?)\s*```", http_section, re.DOTALL)
        ]

        assert len(examples) == 2
        for example in examples:
            assert set(example) == EXPECTED_KEYS
            assert all(set(example) == set(payload) for payload in responses)
    finally:
        server.shutdown()
        server.server_close()

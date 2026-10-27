#!/usr/bin/env python3
"""Check local event examples and alert preservation with JSON Schema."""
import json
from pathlib import Path
from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
api = json.loads((root / "contract/openapi.json").read_text())
schema = json.loads((root / "contract/event-schema.json").read_text())
Draft7Validator.check_schema(schema)
validator = Draft7Validator(schema, format_checker=FormatChecker())
events = {}
for path in sorted((root / "contract/examples").glob("*.json")):
    event = json.loads(path.read_text())
    validator.validate(event)
    events[event["event_id"]] = event
alerts = json.loads((root / "mocks/alerts.json").read_text())["alerts"]
assert len(alerts) == 3
assert len({alert["alert_id"] for alert in alerts}) == 3
for alert in alerts:
    Draft202012Validator(api["components"]["schemas"]["Alert"], format_checker=FormatChecker()).validate(alert)
    event = events[alert["event_id"]]
    assert {key: alert[key] for key in event} == event
    if alert["source"] == "scanner":
        assert alert["source_ip"] is None
        assert alert["target_ip"] == event["details"]["target"]["ip"]
    else:
        assert alert["source_ip"] == event["details"]["source_ip"]
        assert alert["target_ip"] == event["details"].get("target_ip")

def check_refs(value):
    if isinstance(value, dict):
        if "$ref" in value:
            ref = value["$ref"]
            assert ref.startswith("#/")
            target = api
            for token in ref[2:].split("/"):
                target = target[token.replace("~1", "/").replace("~0", "~")]
        for child in value.values():
            check_refs(child)
    elif isinstance(value, list):
        for child in value:
            check_refs(child)
check_refs(api)
assert set(api["paths"]["/events"]["post"]["responses"]) == {"200", "400", "415"}
print("PASS: 3 producer events, 3 complete alerts, IP mapping and all OpenAPI references")

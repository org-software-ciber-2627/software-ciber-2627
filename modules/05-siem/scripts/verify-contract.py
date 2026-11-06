#!/usr/bin/env python3
"""Check local event examples and alert preservation with JSON Schema."""
import json
from pathlib import Path

if not __debug__:
    raise SystemExit("Run without Python optimization; these checks require assertions.")

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
assert set(api["paths"]["/events"]["post"]["responses"]) == {"200", "400", "409", "415", "503"}
api_event = api["components"]["schemas"]["SecurityEvent"]
assert schema["properties"]["severity"]["enum"] == api_event["properties"]["severity"]["enum"] == ["info", "low", "medium", "high", "critical"]
assert api["components"]["schemas"]["Alert"]["properties"]["severity"]["enum"] == ["low", "medium", "high", "critical"]
for event in events.values():
    Draft202012Validator(api_event, format_checker=FormatChecker()).validate(event)
info = json.loads((root / "contract/examples/grupo_4_scanner_info.json").read_text())
assert info["severity"] == "info" and info["source"] == "scanner"
for severity in ("urgent", "INFO", "", None, 42):
    invalid = {**info, "severity": severity}
    assert not validator.is_valid(invalid), "Invalid severity accepted by event schema"
    assert not Draft202012Validator(api_event).is_valid(invalid), "Invalid severity accepted by OpenAPI"
post = api["paths"]["/events"]["post"]
for example in post["requestBody"]["content"]["application/json"]["examples"].values():
    Draft202012Validator(api_event, format_checker=FormatChecker()).validate(example["value"])
for response in post["responses"].values():
    media = response["content"]["application/json"]
    ref = media["schema"]["$ref"].split("/")[-1]
    response_validator = Draft202012Validator(api["components"]["schemas"][ref])
    for example in media.get("examples", {}).values():
        response_validator.validate(example["value"])
    if "example" in media:
        response_validator.validate(media["example"])
print("PASS: " + str(len(events)) + " event examples, static alerts, severity catalogs, rejection cases and OpenAPI references")

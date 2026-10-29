#!/usr/bin/env python3
"""Check local event examples and alert preservation with JSON Schema."""
import argparse
import copy
import json
from urllib.parse import parse_qs, urlsplit
from pathlib import Path

if not __debug__:
    raise SystemExit("Run without Python optimization; these checks require assertions.")

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker, ValidationError

parser = argparse.ArgumentParser(description="Validate SIEM event, alert and history contracts.")
parser.add_argument("--history-responses", type=Path, help="JSON array of observed history status/body records.")
args = parser.parse_args()
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
history = api["paths"]["/events"]["get"]
assert set(history["responses"]) == {"200", "400", "500", "503"}
assert {parameter["name"] for parameter in history["parameters"]} == {"limit", "offset"}


def resolve_local_refs(value):
    if isinstance(value, dict):
        result = {}
        if "$ref" in value:
            target = api
            for token in value["$ref"][2:].split("/"):
                target = target[token.replace("~1", "/").replace("~0", "~")]
            result.update(resolve_local_refs(target))
        result.update({key: resolve_local_refs(child) for key, child in value.items() if key != "$ref"})
        return result
    if isinstance(value, list):
        return [resolve_local_refs(child) for child in value]
    return value


def history_validator(status):
    schema = resolve_local_refs(history["responses"][str(status)]["content"]["application/json"]["schema"])
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_history(status, body):
    history_validator(status).validate(body)
    if status == 200 and body["next"] is not None:
        link = urlsplit(body["next"])
        assert not link.scheme and not link.netloc and not link.fragment
        values = parse_qs(link.query, strict_parsing=True)
        assert set(values) == {"limit", "offset"} and all(len(value) == 1 for value in values.values())
        limit, offset = int(values["limit"][0]), int(values["offset"][0])
        assert 1 <= limit <= 500 and len(body["events"]) == limit
        assert offset == body["next_offset"]


# Check every local component and documented JSON example, including inherited POST behavior.
for schema in api["components"]["schemas"].values():
    Draft202012Validator.check_schema(resolve_local_refs(schema))
for path in api["paths"].values():
    for operation in path.values():
        bodies = list(operation.get("responses", {}).values())
        if "requestBody" in operation:
            bodies.append(operation["requestBody"])
        for body in bodies:
            media = body.get("content", {}).get("application/json")
            if not media:
                continue
            example_validator = Draft202012Validator(resolve_local_refs(media["schema"]), format_checker=FormatChecker())
            if "example" in media:
                example_validator.validate(media["example"])
            for example in media.get("examples", {}).values():
                example_validator.validate(example["value"])


for response in history["responses"].values():
    assert response["headers"]["Cache-Control"]["schema"]["const"] == "no-store"
    media = response["content"]["application/json"]
    validator = Draft202012Validator(resolve_local_refs(media["schema"]), format_checker=FormatChecker())
    for example in media.get("examples", {}).values():
        validator.validate(example["value"])
    if "example" in media:
        validator.validate(media["example"])

sample = copy.deepcopy(history["responses"]["200"]["content"]["application/json"]["examples"]["continuation"]["value"])
validate_history(200, sample)
for external_link in ("//domain.local/events?limit=1&offset=1", "https://domain.local/events?limit=1&offset=1",
                      "/\\domain.local/events?limit=1&offset=1"):
    assert not history_validator(200).is_valid({**sample, "next": external_link}), "Origin escape accepted by schema"
invalid_pages = [
    {"events": [], "next_offset": None},
    {"events": [], "next_offset": None, "next": "/events?limit=1&offset=1"},
    {"events": [], "next_offset": 1, "next": "/events?limit=1&offset=1"},
    {**sample, "unexpected": True},
    {**sample, "next_offset": 2},
    {**sample, "next": "https://untrusted.domain.local/events?limit=1&offset=1"},
    {**sample, "events": sample["events"] * 501},
    {**sample, "events": [{"event_id": "incomplete"}]},
]
for invalid in invalid_pages:
    try:
        validate_history(200, invalid)
    except (AssertionError, ValueError, ValidationError):
        continue
    raise AssertionError("Invalid history response was accepted")

if args.history_responses:
    observed = json.loads(args.history_responses.read_text())
    assert observed, "No observed history responses"
    for record in observed:
        validate_history(record["status"], record["body"])
        assert record["headers"]["Cache-Control"] == "no-store"
        assert record["headers"]["Content-Type"].split(";", 1)[0].lower() == "application/json"
    print("PASS: " + str(len(observed)) + " observed HTTP history responses match OpenAPI")
print("PASS: producer events, static alerts, references and positive/negative history contract checks")

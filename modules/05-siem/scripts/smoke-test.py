#!/usr/bin/env python3
"""Exercise the deployed SIEM mock using only the Python standard library."""
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

root = Path(__file__).resolve().parents[1]
base = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8005").rstrip("/")
checks = []
def request(path, body=None, content_type="application/json"):
    data = body.encode() if body is not None else None
    req = Request(base + path, data=data, headers={"Content-Type": content_type} if data is not None else {})
    try:
        with urlopen(req, timeout=10) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)

def check(name, condition):
    assert condition, name
    checks.append(name)

status, body = request("/health")
check("health identifies 05-siem", status == 200 and body == {"status":"ok", "module":"05-siem"})
fixture = json.loads((root / "mocks/alerts.json").read_text())
status, body = request("/alerts")
check("three full static alerts", status == 200 and body == fixture and len(body["alerts"]) == 3)
for path in sorted((root / "contract/examples").glob("*.json")):
    event = json.loads(path.read_text())
    status, body = request("/events", path.read_text())
    check("POST " + event["source"], status == 200 and body["event_id"] == event["event_id"] and body["status"] == "success")
for alert in fixture["alerts"]:
    status, body = request("/alerts/" + alert["alert_id"])
    check("detail " + alert["source"], status == 200 and body == alert)
status, body = request("/alerts/UNKNOWN")
check("unknown alert returns JSON 404", status == 404 and body["error"]["code"] == "ALERT_NOT_FOUND")
for invalid in ["{", "{}", "[]", "null"]:
    status, body = request("/events", invalid)
    check("invalid event " + invalid, status == 400 and "error" in body)
status, body = request("/events", "test", "text/plain")
check("unsupported content type", status == 415 and body["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE")
status, body = request("/alerts")
check("POST does not mutate static alerts", status == 200 and body == fixture)
print(json.dumps({"result":"PASS", "base_url":base, "checks":checks, "count":len(checks)}, ensure_ascii=False, indent=2))

#!/usr/bin/env python3
"""Exercise an unchanged scanner snapshot against an isolated SIEM and target."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time
import uuid

MODULE = Path(__file__).resolve().parents[1]
ROOT = MODULE.parents[1]
REPORT = MODULE / "target/sem96/report.json"
SCANNER = "f04a1efd16fde000ddaee16711f00de86ee91b81"
IMAGES = ["postgres:17-alpine", "python:3.12-slim", "eclipse-temurin:21-jre-alpine",
          "vulhub/openssl:1.0.1c-with-nginx"]

# This observer forwards real HTTP requests. It does not repair the producer.
RELAY = r'''import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
records = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        body = json.dumps(records).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        event = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        try:
            with urlopen(Request("http://siem/events", data=json.dumps(event).encode(),
                                 headers={"Content-Type": "application/json"}), timeout=2) as response:
                status, body = response.status, response.read()
        except HTTPError as error:
            status, body = error.code, error.read()
        except (URLError, TimeoutError):
            status, body = 502, b'{"error":"UPSTREAM_UNAVAILABLE"}'
        records.append({"event": event, "status": status, "receipt": json.loads(body)})
        self.send_response(status); self.end_headers(); self.wfile.write(body)
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
CLIENT = r'''import json, sys
from urllib.request import Request, urlopen
url, payload = sys.argv[1:]
request = Request(url, data=payload.encode() if payload else None,
                  headers={"Content-Type": "application/json"})
with urlopen(request, timeout=5) as response:
    print(response.read().decode())
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command_run(command, env, timeout=180, input=None, check=True):
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, input=input,
                                   capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Command timed out: " + command[0]) from None
    except OSError:
        raise RuntimeError("Command could not start: " + command[0]) from None
    if check and completed.returncode:
        raise RuntimeError("Command failed: " + " ".join(command[:2]) +
                           " (exit " + str(completed.returncode) + ")")
    return completed


def cleanup_resources(run, containers, network, images):
    errors = []
    resources = [("container", name, ["rm", "-f", "-v", name]) for name in reversed(containers)]
    resources += [("network", network, ["network", "rm", network])]
    resources += [("image", image, ["image", "rm", image]) for image in reversed(images)]
    for kind, name, removal in resources:
        try:
            inspected = run("docker", kind, "inspect", name, check=False, timeout=20)
            if inspected.returncode:
                # Only a known not-found response means absence. Connection errors do not.
                missing = ("No such " + kind) in inspected.stderr or "No such object" in inspected.stderr
                if not missing:
                    errors.append(kind + " " + name + ": inspection failed")
                continue
            removed = run("docker", *removal, check=False, timeout=30)
            if removed.returncode:
                errors.append(kind + " " + name + ": removal failed")
        except Exception:
            errors.append(kind + " " + name + ": cleanup command failed")
    return errors


def main():
    REPORT.unlink(missing_ok=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Use cached Maven dependencies.")
    parser.add_argument("--scan-timeout", type=int, default=600)
    args = parser.parse_args()
    require(30 <= args.scan_timeout <= 900, "Scan timeout must be between 30 and 900 seconds")
    env = {k: v for k, v in os.environ.items() if not k.startswith(
        ("SIEM_", "SPRING_", "SERVER_", "PG", "COMPOSE_")) and k not in
        ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "MAVEN_OPTS", "MAVEN_ARGS")}
    password = secrets.token_hex(24)
    prefix = "sem96-" + uuid.uuid4().hex[:10]
    containers, images_added = [], []
    network = prefix + "-net"
    scanner_image = prefix + ":scanner"
    result = {"status": "failed", "scanner_commit": SCANNER, "checks": [], "limitations": []}

    def run(*command, timeout=180, input=None, check=True):
        return command_run(command, env, timeout=timeout, input=input, check=check)

    def docker(*arguments, **kwargs):
        return run("docker", *arguments, **kwargs).stdout.strip()

    def passed(name):
        result["checks"].append(name)
        print("PASS " + name, flush=True)

    def container(role, image, *arguments, isolated=True, extra=()):
        name = prefix + "-" + role
        containers.append(name)
        options = ["run", "-d", "--name", name, "--label", "siem.sem96=" + prefix]
        if isolated:
            options += ["--network", network, "--network-alias", role]
        docker(*options, *extra, image, *arguments)
        return name

    def wait_for(function, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                value = function()
                if value:
                    return value
            except (RuntimeError, json.JSONDecodeError):
                pass
            time.sleep(1)
        raise RuntimeError("Timed out waiting for lab readiness")

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Lab interrupted")

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)

    try:
        docker("info", timeout=20)
        result["siem_commit"] = run("git", "rev-parse", "HEAD").stdout.strip()
        result["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        for image in IMAGES:
            if run("docker", "image", "inspect", image, check=False).returncode:
                images_added.append(image)
                platform = ["--platform", "linux/amd64"] if image.startswith("vulhub/") else []
                docker("pull", *platform, image, timeout=300)
        result["images"] = {image: json.loads(docker("image", "inspect", image))[0]["Id"] for image in IMAGES}
        print("Building the current SIEM artifact", flush=True)
        built = run(str(MODULE / "mvnw"), "-f", str(MODULE / "pom.xml"),
                    *(["-o"] if args.offline else []), "--batch-mode", "package", "-DskipTests", timeout=600)
        require("BUILD SUCCESS" in built.stdout, "SIEM packaging did not succeed")
        result["packaging_skips_tests"] = True
        with tempfile.TemporaryDirectory(prefix="sem96-") as directory:
            here = Path(directory)
            snapshot = here / "scanner"
            snapshot.mkdir()
            # git archive is consumed by tar outside the checkout; no G4 file is modified.
            with (here / "scanner.tar").open("wb") as stream:
                subprocess.run(["git", "archive", SCANNER, "modules/04-escaner"],
                               cwd=ROOT, stdout=stream, check=True, timeout=30)
            run("tar", "-xf", str(here / "scanner.tar"), "-C", str(snapshot))
            source = snapshot / "modules/04-escaner"
            (here / "relay.py").write_text(RELAY)
            provision = container("provision", "python:3.12-slim", "sleep", "infinity", isolated=False)
            docker("exec", provision, "sh", "-c",
                   "apt-get update -qq && apt-get install -y --no-install-recommends nmap "
                   "&& pip install --no-cache-dir flask requests && rm -rf /var/lib/apt/lists/*", timeout=600)
            images_added.append(scanner_image)
            docker("commit", provision, scanner_image)
            result["nmap_version"] = docker("exec", provision, "nmap", "--version").splitlines()[0]
            result["scanner_packages"] = docker("exec", provision, "pip", "freeze").splitlines()
            docker("rm", "-f", provision)
            docker("network", "create", "--internal", "--label", "siem.sem96=" + prefix, network)
            db = container("db", IMAGES[0], extra=("-e", "POSTGRES_USER=siem", "-e",
                "POSTGRES_DB=siem_bd", "-e", "POSTGRES_PASSWORD=" + password,
                "--mount", "type=bind,src=" + str(MODULE / "db/init") +
                ",dst=/docker-entrypoint-initdb.d,readonly"))
            wait_for(lambda: run("docker", "exec", db, "pg_isready", "-h", "127.0.0.1", "-U", "siem", "-d", "siem_bd", check=False).returncode == 0)
            jar = MODULE / "target/siem-0.0.1-SNAPSHOT.jar"
            result["siem_jar_sha256"] = hashlib.sha256(jar.read_bytes()).hexdigest()
            siem = container("siem", IMAGES[2], "java", "-jar", "/app.jar", extra=(
                "--mount", "type=bind,src=" + str(jar) + ",dst=/app.jar,readonly",
                "-e", "SERVER_PORT=80", "-e", "SPRING_PROFILES_ACTIVE=persistence",
                "-e", "SIEM_DB_URL=jdbc:postgresql://db:5432/siem_bd", "-e", "SIEM_DB_PASSWORD=" + password))
            relay = container("relay", scanner_image, "python", "/relay.py", extra=(
                "--mount", "type=bind,src=" + str(here / "relay.py") + ",dst=/relay.py,readonly"))
            scanner = container("scanner", scanner_image, "python", "/src/main.py", extra=(
                "--mount", "type=bind,src=" + str(source / "src") + ",dst=/src,readonly",
                "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "SIEM_URL=http://relay:8080/events"))
            target = container("target", IMAGES[3], extra=("--platform", "linux/amd64"))

            def http(url, payload=None):
                return json.loads(docker("exec", scanner, "python", "-c", CLIENT, url,
                                         json.dumps(payload) if payload is not None else "", timeout=15))

            wait_for(lambda: http("http://siem/health"))
            wait_for(lambda: isinstance(http("http://scanner:8004/events"), (dict, list)))
            # Check TCP readiness without disabling TLS verification in production clients.
            wait_for(lambda: docker("exec", scanner, "python", "-c",
                "import socket; socket.create_connection(('target',443),2).close(); print('ready')"))
            passed("isolated services ready without published host ports")

            def scan(profile):
                job = http("http://scanner:8004/scan", {"target": "target", "profile": profile})
                scan_id = job["scan_id"]
                def finished():
                    state = http("http://scanner:8004/scan/" + scan_id)
                    return state if state["status"] in ("completed", "failed") else None
                state = wait_for(finished, args.scan_timeout)
                require(state["status"] == "completed" and state["events"], "Scanner did not generate events")
                return state

            def records_for(job):
                ids = {event["event_id"] for event in job["events"]}
                return [record for record in http("http://relay:8080/records")
                        if record["event"]["event_id"] in ids]

            def delivered(job):
                return wait_for(lambda: (records if len(records := records_for(job)) == len(job["events"]) else None), 90)

            inventory = scan("quick")
            inventory_records = delivered(inventory)
            require(any(event["severity"] == "info" for event in inventory["events"]), "Inventory has no info event")
            passed("real inventory scan generates info events")
            finding = scan("vuln")
            finding_records = delivered(finding)
            heartbleed = [event for event in finding["events"] if
                event["event_type"] == "cve_detected" and event["details"]["cve"] == "CVE-2014-0160"
                and event["details"]["script_id"] == "ssl-heartbleed"
                and "VULNERABLE" in event["details"]["evidence"]]
            require(heartbleed, "Real scan did not detect the expected Heartbleed vulnerability")
            passed("real Nmap scan generates a Heartbleed finding through unchanged G4")
            all_records = inventory_records + finding_records
            generated = {event["event_id"]: event for event in inventory["events"] + finding["events"]}
            require(len(generated) == len(all_records), "Generated event identities are not unique")
            require(all(generated.get(record["event"]["event_id"]) == record["event"] for record in all_records),
                    "Forwarded payload differs from the generated event")
            for record in all_records:
                require(record["status"] == 200 and record["receipt"].get("event_id") == record["event"]["event_id"]
                        and record["receipt"].get("status") == "success", "Receipt does not confirm the generated event")
            passed("every generated event receives HTTP 200 and a matching event_id")

            def rows():
                statement = "SELECT COALESCE(json_agg(json_build_object('event_id',event_id,'timestamp',original_timestamp," \
                    "'source',source,'event_type',event_type,'severity',severity,'title',title," \
                    "'description',description,'details',details)), '[]'::json) FROM events;"
                return json.loads(docker("exec", "-i", db, "psql", "-X", "-U", "siem", "-d", "siem_bd",
                                         "-At", "-v", "ON_ERROR_STOP=1", input=statement))
            stored = {row["event_id"]: row for row in rows()}
            for record in all_records:
                event = record["event"]
                require(stored.get(event["event_id"]) == event, "Stored event differs from the producer payload")
            require(len(stored) == len(all_records), "Unexpected stored event count")
            passed("PostgreSQL preserves every complete event including nested details and nulls")
            replay = http("http://siem/events", inventory["events"][0])
            require(replay.get("event_id") == inventory["events"][0]["event_id"] and len(rows()) == len(stored),
                    "Replay did not preserve idempotent storage")
            passed("replaying a real event does not create an extra row")
            docker("stop", siem)
            failed_delivery = scan("quick")
            failure_records = delivered(failed_delivery)
            require(all(record["status"] == 502 for record in failure_records), "Controlled upstream failure not observed")
            require(len(rows()) == len(stored), "Unavailable SIEM unexpectedly stored events")
            passed("controlled SIEM outage is observed externally and adds no rows")
            result["limitations"].append("G4 marks the scan completed despite every delivery receiving HTTP 502; it does not validate receipts.")
            result["counts"] = {"inventory_events": len(inventory_records), "finding_events": len(finding_records),
                                "heartbleed_events": len(heartbleed), "stored_events": len(stored),
                                "failed_delivery_events": len(failure_records)}
            result["status"] = "passed_with_producer_limitation"
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error).replace(password, "[redacted]")
        raise
    finally:
        # Attempt every cleanup step, including after setup failures or an interrupted scan.
        cleanup_errors = cleanup_resources(run, containers, network, images_added)
        result["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            result["status"] = "cleanup_failed"
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(result, indent=2) + "\n")
        require(not cleanup_errors, "Lab resource cleanup failed; inspect report")
    print("Report: " + str(REPORT), flush=True)


if __name__ == "__main__":
    main()

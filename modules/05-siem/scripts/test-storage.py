#!/usr/bin/env python3
"""Reproducible SEM-66 checks; never uses the developer database or .env."""
import argparse
import json
import xml.etree.ElementTree as ET
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import uuid

MODULE = Path(__file__).resolve().parents[1]
ROOT = MODULE.parents[1]
REPORT = MODULE / 'target/sem66/report.json'
# Invalidate old success evidence even when argument validation rejects this run.
REPORT.unlink(missing_ok=True)
parser = argparse.ArgumentParser(description="Run SIEM storage checks in an isolated PostgreSQL project.")
parser.add_argument("--offline", action="store_true", help="Use Maven's local dependency cache.")
args = parser.parse_args()
if not __debug__:
    parser.error("Run without Python optimization; these checks require assertions.")
PROJECT = 'grupo5-siem-test-' + uuid.uuid4().hex[:12]
ENV = {name: value for name, value in os.environ.items()
       if not name.startswith(('COMPOSE_', 'SPRING_', 'SIEM_', 'SERVER_', 'PG'))
       and name not in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'MAVEN_ARGS', 'MAVEN_OPTS')}
ENV['SIEM_DB_PASSWORD'] = secrets.token_hex(24)
ENV['SIEM_DB_NAME'] = 'siem_bd'
checks = []


def passed(name):
    checks.append(name)
    print('PASS ' + name, flush=True)


def verify_java_reports():
    reports = list((MODULE / 'target/surefire-reports').glob('TEST-*.xml'))
    suites = {ET.parse(path).getroot().attrib['name']: ET.parse(path).getroot().attrib for path in reports}
    for required in ('PostgresEventRepositoryTests', 'PersistentEventHttpTests', 'EventServiceLoggingTests'):
        assert any(name.endswith('.' + required) and int(attributes['tests']) > 0
                   for name, attributes in suites.items()), 'Missing test suite: ' + required
    totals = {key: sum(int(attributes.get(key, 0)) for attributes in suites.values())
              for key in ('tests', 'failures', 'errors', 'skipped')}
    assert reports and totals['tests'] > 0 and not any(totals[key] for key in ('failures', 'errors', 'skipped')), totals
    return totals

script_tests = subprocess.run(
    [sys.executable, '-m', 'unittest', 'discover', '-s', str(MODULE / 'scripts'), '-p', 'test_*.py', '-v'],
    cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=60)
if script_tests.returncode:
    raise RuntimeError('Verification script regressions failed:\n' + script_tests.stderr[-6000:])
passed('verification script regressions reject false success and stale reports')

with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0))
    ENV['SIEM_DB_PORT'] = str(probe.getsockname()[1])

with tempfile.TemporaryDirectory(prefix='grupo5-siem-') as directory:
    HERE = Path(directory)
    initial = HERE / 'init'
    initial.mkdir()
    shutil.copyfile(MODULE / 'db/init/001-create-events.sql', initial / '001-create-events.sql')
    override = Path(directory) / 'override.json'
    override.write_text(json.dumps({'services': {'siem-db': {'volumes': [
        {'type': 'bind', 'source': str(initial), 'target': '/docker-entrypoint-initdb.d', 'read_only': True}
    ]}}}))
    base = ['docker', 'compose', '--env-file', '/dev/null', '-f', str(ROOT / 'docker-compose.yml'),
            '-f', str(override), '-p', PROJECT, '--profile', 'siem-db']

    def compose(*arguments, timeout=120, **kwargs):
        result = subprocess.run(base + list(arguments), cwd=ROOT, env=ENV, capture_output=True,
                                text=True, timeout=timeout, **kwargs)
        if result.returncode:
            raise RuntimeError(result.stderr.replace(ENV['SIEM_DB_PASSWORD'], '[redacted]'))
        return result.stdout

    def sql(statement):
        return compose('exec', '-T', 'siem-db', 'psql', '-X', '-U', 'siem', '-d', ENV['SIEM_DB_NAME'],
                       '-v', 'ON_ERROR_STOP=1', '-At', input=statement).strip()

    try:
        compose('up', '-d', '--wait', '--wait-timeout', '90', 'siem-db', timeout=180)
        assert sql('SELECT current_database()') == ENV['SIEM_DB_NAME']
        passed('configured database name is siem_bd')
        sql("INSERT INTO events VALUES ('sem65-migration-check', '2026-10-20T12:00:00Z', "
            "'ids', 'port_scan', 'medium', 'Migration check', 'Existing event', '{}')")
        migration = (MODULE / 'db/init/002-add-original-timestamp.sql').read_text()
        sql(migration)
        sql(migration)
        result = sql("SELECT count(*) FROM events WHERE event_id='sem65-migration-check' "
                     "AND source='ids' AND occurred_at='2026-10-20T12:00:00Z' "
                     "AND details='{}'::jsonb AND original_timestamp IS NULL")
        assert result == '1', 'Migration changed the existing event'
        passed('additive migration preserves an existing event and can be reapplied')
        test_env = ENV.copy()
        test_env['SIEM_TEST_DB_URL'] = 'jdbc:postgresql://127.0.0.1:' + ENV['SIEM_DB_PORT'] + '/' + ENV['SIEM_DB_NAME']
        test_env['SIEM_TEST_DB_USER'] = 'siem'
        test_env['SIEM_TEST_DB_PASSWORD'] = ENV['SIEM_DB_PASSWORD']
        with (HERE / 'java-tests.log').open('w') as log:
            tested = subprocess.run(['./mvnw'] + (['-o'] if args.offline else []) + ['--batch-mode', 'clean', 'verify'], cwd=MODULE, env=test_env,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=600)
        for line in (HERE / 'java-tests.log').read_text().splitlines():
            if 'Tests run:' in line or 'BUILD SUCCESS' in line or 'BUILD FAILURE' in line:
                print(line, flush=True)
        if tested.returncode:
            raise RuntimeError('Java tests failed:\n' + (HERE / 'java-tests.log').read_text()[-6000:].replace(ENV['SIEM_DB_PASSWORD'], '[redacted]'))
        totals = verify_java_reports()
        passed('Java suites ran with PostgreSQL enabled and no skipped tests')

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            http_port = probe.getsockname()[1]
        app_env = ENV.copy()
        app_env['SPRING_PROFILES_ACTIVE'] = 'persistence'
        app_env['SERVER_PORT'] = str(http_port)
        base_url = 'http://127.0.0.1:' + str(http_port)

        def request(path, event=None):
            data = json.dumps(event).encode() if event else None
            req = Request(base_url + path, data=data,
                          headers={'Content-Type': 'application/json'} if data else {})
            try:
                with urlopen(req, timeout=10) as response:
                    return response.status, json.load(response)
            except HTTPError as error:
                return error.code, json.load(error)

        with (HERE / 'application.log').open('w') as app_log:
            app = subprocess.Popen(['java', '-jar', str(MODULE / 'target/siem-0.0.1-SNAPSHOT.jar'), '--server.address=127.0.0.1'],
                                   cwd=MODULE, env=app_env, stdout=app_log, stderr=subprocess.STDOUT)
            try:
                for attempt in range(100):
                    if app.poll() is not None:
                        raise RuntimeError('Packaged application exited during startup')
                    try:
                        if request('/health')[0] == 200:
                            break
                    except (URLError, ConnectionError):
                        time.sleep(0.2)
                else:
                    raise RuntimeError('Packaged application did not become available')
                event = json.loads((MODULE / 'contract/examples/grupo_3_honeypot.json').read_text())
                event['event_id'] = PROJECT + '-http-recovery'
                event['timestamp'] = '2026-10-23T12:00:00.123456789Z'
                event['details'] = {'nested': [None, True, {'text': 'ñ'}]}
                assert request('/events', event)[0] == 200
                history_status, history = request('/events?limit=1&offset=0')
                assert history_status == 200 and history['events'] == [event], (history_status, history)
                passed('packaged history returns the complete persisted event')
                assert sql("SELECT count(*) FROM events WHERE event_id='" + event['event_id'] + "'") == '1'
                before = sql("SELECT row_to_json(events)::text FROM events WHERE event_id='" + event['event_id'] + "'")
                compose('stop', 'siem-db')
                status, body = request('/events', event)
                assert status == 503 and body['error']['code'] == 'STORAGE_UNAVAILABLE', (status, body)
                passed('packaged HTTP application returns 503 during a real PostgreSQL outage')
                history_status, history = request('/events')
                assert history_status == 503 and history['error']['code'] == 'STORAGE_UNAVAILABLE', (history_status, history)
                passed('history reports storage outage instead of empty success')
                compose('rm', '-f', 'siem-db')
                compose('up', '-d', '--wait', '--wait-timeout', '90', 'siem-db', timeout=180)
                assert sql("SELECT row_to_json(events)::text FROM events WHERE event_id='" + event['event_id'] + "'") == before, 'Container recreation changed stored data'
                passed('container recreation preserves all stored columns on the same isolated volume')
                history_status, history = request('/events?limit=1&offset=0')
                assert history_status == 200 and history['events'] == [event], (history_status, history)
                passed('history remains available with identical data after storage recovery')
                assert request('/events', event)[0] == 200
                assert sql("SELECT count(*) FROM events WHERE event_id='" + event['event_id'] + "'") == '1'
                event['title'] = 'Changed after database restart'
                assert request('/events', event)[0] == 409
                passed('recovery accepts identical replay with one row and rejects changed content')
                smoke = subprocess.run(['python3', str(MODULE / 'scripts/smoke-test.py'), base_url],
                                       capture_output=True, text=True, timeout=30)
                (HERE / 'smoke-test.json').write_text(smoke.stdout)
                assert smoke.returncode == 0, smoke.stderr
                smoke_count = json.loads(smoke.stdout)['count']
                passed('packaged application HTTP smoke checks: ' + str(smoke_count))
            finally:
                app.terminate()
                try:
                    app.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait(timeout=5)

    finally:
        compose('down', '-v', '--remove-orphans')
        passed('only isolated test project containers, network and volume removed')

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps({'status': 'passed', 'java': totals, 'http_smoke_checks': smoke_count,
                              'checks': checks}, indent=2) + '\n')
print('Report: ' + str(REPORT), flush=True)

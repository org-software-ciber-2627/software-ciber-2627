import os
import tempfile
import threading
import urllib.error
import urllib.request
import uuid
import json

from parser import parse_xml
from runner import start_nmap

JOBS = {}
SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")


def publish_events_to_siem(events):
    for event in events:
        payload = json.dumps(event).encode("utf-8")
        request = urllib.request.Request(
            SIEM_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=3):
                pass
        except (urllib.error.URLError, TimeoutError):
            pass


def _run_job_worker(scan_id, target, profile, xml_outfile):
    try:
        process = start_nmap(target, profile, xml_outfile)
        process.wait()

        if os.path.exists(xml_outfile):
            with open(xml_outfile, "r", encoding="utf-8") as xml_file:
                xml_content = xml_file.read()
            JOBS[scan_id]["events"] = parse_xml(xml_content, scan_id, profile)

        JOBS[scan_id]["status"] = "completed"
        publish_events_to_siem(JOBS[scan_id]["events"])

    except Exception as error:
        JOBS[scan_id]["status"] = "failed"
        JOBS[scan_id]["error"] = str(error)
    finally:
        if os.path.exists(xml_outfile):
            os.remove(xml_outfile)


def create_job(target, profile):
    scan_id = str(uuid.uuid4())
    descriptor, xml_outfile = tempfile.mkstemp(suffix=".xml")
    os.close(descriptor)

    job = {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "status": "running",
        "events": [],
    }
    JOBS[scan_id] = job

    worker = threading.Thread(target=_run_job_worker, args=(scan_id, target, profile, xml_outfile), daemon=True)
    worker.start()

    return job


def get_job(scan_id):
    return JOBS.get(scan_id)


def public(job):
    if job is None:
        return None
    return {
        "scan_id": job["scan_id"],
        "target": job["target"],
        "profile": job["profile"],
        "status": job["status"],
        "events": job.get("events", []),
    }

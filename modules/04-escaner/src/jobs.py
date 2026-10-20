import uuid
import tempfile
import os
import requests
import threading
from runner import start_nmap
from parser import parse_xml

JOBS = {}  # estructura temporal que actúa como BBDD en memoria
SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")

def publish_events_to_siem(events):
    """Envía los hallazgos en formato común mediante POST /events hacia el SIEM."""
    for event in events:
        try:
            requests.post(SIEM_URL, json=event, timeout=3)
        except requests.exceptions.RequestException:
            # Si el SIEM no está disponible, no rompemos la ejecución
            pass

def _run_job_worker(scan_id, target, profile, xml_outfile):
    """Función que ejecuta Nmap y parsea el resultado en un hilo separado (segundo plano)."""
    try:
        proc = start_nmap(target, profile, xml_outfile)
        proc.wait()

        if os.path.exists(xml_outfile):
            with open(xml_outfile, "r", encoding="utf-8") as f:
                xml_content = f.read()
            JOBS[scan_id]["events"] = parse_xml(xml_content, scan_id, profile)

        JOBS[scan_id]["status"] = "completed"
        publish_events_to_siem(JOBS[scan_id]["events"])

    except Exception as e:
        JOBS[scan_id]["status"] = "failed"
        JOBS[scan_id]["error"] = str(e)
    finally:
        if os.path.exists(xml_outfile):
            os.remove(xml_outfile)

def create_job(target, profile):
    scan_id = str(uuid.uuid4())
    fd, xml_outfile = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    job = {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "status": "running",
        "events": []
    }
    JOBS[scan_id] = job

    # Lanzamos el proceso en segundo plano (daemon thread) para responder de inmediato
    t = threading.Thread(target=_run_job_worker, args=(scan_id, target, profile, xml_outfile))
    t.daemon = True
    t.start()

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
        "events": job.get("events", [])
    }

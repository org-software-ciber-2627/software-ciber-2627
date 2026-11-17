import uuid
import tempfile
import os
import requests
import threading
import subprocess
from xml.etree.ElementTree import ParseError
from runner import NMAP_TIMEOUT_SECONDS, start_nmap
from parser import parse_xml
from datetime import datetime, timezone


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
    try:
        try:
            process = start_nmap(target, profile, xml_outfile)
        except OSError as error:
            raise RuntimeError("No se pudo iniciar Nmap; comprueba que esté instalado") from error

        try:
            process.communicate(timeout=NMAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            # Si vence el límite, no dejamos Nmap huérfano.
            process.kill()
            process.communicate()
            raise RuntimeError(
                f"El escaneo superó el límite de {NMAP_TIMEOUT_SECONDS} segundos"
            ) from error

        if process.returncode != 0:
            raise RuntimeError(f"Nmap terminó con código {process.returncode}")

        if not os.path.isfile(xml_outfile) or os.path.getsize(xml_outfile) == 0:
            raise RuntimeError("Nmap terminó sin generar un informe XML")

        try:
            with open(xml_outfile, "r", encoding="utf-8") as xml_file:
                xml_content = xml_file.read()
        except OSError as error:
            raise RuntimeError("No se pudo leer el informe XML de Nmap") from error
        JOBS[scan_id]["events"] = parse_xml(xml_content, scan_id, profile)

        JOBS[scan_id]["status"] = "completed"
        publish_events_to_siem(JOBS[scan_id]["events"])

    except Exception as error:
        JOBS[scan_id]["status"] = "failed"
        # No se devuelve stderr ni detalles del entorno a los consumidores de la API.
        if isinstance(error, (RuntimeError, ParseError)):
            message = str(error)
        else:
            message = "Error interno al ejecutar o procesar Nmap"
        JOBS[scan_id]["error"] = message or "Error al ejecutar o procesar Nmap"
    finally:
        if os.path.exists(xml_outfile):
            try:
                os.remove(xml_outfile)
            except OSError:
                pass

def create_job(target, profile):
    scan_id = str(uuid.uuid4())
    fd, xml_outfile = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    job = {
        "scan_id": scan_id,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
    result = {
        "scan_id": job["scan_id"],
        "created_at": job.get("created_at"),
        "target": job["target"],
        "profile": job["profile"],
        "status": job["status"],
        "events": job.get("events", [])
    }
    if job.get("status") == "failed":
        result["error"] = job.get("error", "El escaneo ha fallado")
    return result

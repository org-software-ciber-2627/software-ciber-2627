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
import logging

logger = logging.getLogger(__name__)

JOBS = {}  # estructura temporal que actúa como BBDD en memoria
SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")

def publish_events_to_siem(events, scan_id=None):
    """Envía cada evento individualmente mediante POST /events hacia el SIEM, comprueba el acuse y registra fallos."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    delivered = 0
    errors = []
    
    for event in events:
        sent_event_id = event.get("event_id")
        try:
            response = requests.post(
                SIEM_URL,
                json=event,
                headers=headers,
                timeout=3,
            )
            if response.status_code != 200:
                errors.append({
                    "event_id": sent_event_id,
                    "code": "http_error",
                    "status_code": response.status_code,
                })
                logger.warning(
                    "Fallo al publicar evento en SIEM (scan_id=%s, event_id=%s, status=%s)",
                    scan_id,
                    sent_event_id,
                    response.status_code,
                )
                continue

            try:
                ack = response.json()
            except ValueError:
                errors.append({
                    "event_id": sent_event_id,
                    "code": "invalid_json_ack",
                })
                logger.warning(
                    "Acuse del SIEM no es JSON válido (scan_id=%s, event_id=%s)",
                    scan_id,
                    sent_event_id,
                )
                continue

            if not isinstance(ack, dict):
                errors.append({
                    "event_id": sent_event_id,
                    "code": "invalid_ack",
                })
                logger.warning(
                    "Acuse del SIEM no es un objeto JSON "
                    "(scan_id=%s, event_id=%s)",
                    scan_id,
                    sent_event_id,
                )
                continue

            if ack.get("status") != "success":
                errors.append({
                    "event_id": sent_event_id,
                    "code": "invalid_ack_status",
                })
                logger.warning(
                    "Acuse del SIEM con status no válido "
                    "(scan_id=%s, event_id=%s, status=%s)",
                    scan_id,
                    sent_event_id,
                    ack.get("status"),
                )
                continue

            ack_event_id = ack.get("event_id")
            if (
                not isinstance(ack_event_id, str)
                or not ack_event_id.strip()
                or ack_event_id != sent_event_id
            ):
                errors.append({
                    "event_id": sent_event_id,
                    "code": "event_id_mismatch",
                })
                logger.warning(
                    "Acuse del SIEM con event_id no coincidente "
                    "(scan_id=%s, event_id=%s, ack_event_id=%s)",
                    scan_id,
                    sent_event_id,
                    ack_event_id,
                )
                continue
                
            delivered += 1
        
        except requests.exceptions.RequestException as exc:
            errors.append({
                "event_id": sent_event_id,
                "code": "connection_error",
                "error_type": type(exc).__name__,
            })
            logger.warning(
                "Error de conexión o timeout al publicar evento en SIEM (scan_id=%s, event_id=%s, error=%s)",
                scan_id,
                sent_event_id,
                type(exc).__name__,
            )

    failed = len(errors)

    if not events:
        delivery_status = "not_required"
    elif failed == 0:
        delivery_status = "delivered"
    elif delivered == 0:
        delivery_status = "failed"
    else:
        delivery_status = "partial"

    return {
        "status": delivery_status,
        "total": len(events),
        "delivered": delivered,
        "failed": failed,
        "errors": errors,
    }

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

        JOBS[scan_id]["siem_delivery"] = publish_events_to_siem(
            JOBS[scan_id]["events"],
            scan_id=scan_id,
        )
        JOBS[scan_id]["status"] = "completed"

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
    if "siem_delivery" in job:
        result["siem_delivery"] = job["siem_delivery"]
    if job.get("status") == "failed":
        result["error"] = job.get("error", "El escaneo ha fallado")
    return result

import uuid
import tempfile
import os
import requests
import threading
import subprocess
from xml.etree.ElementTree import ParseError
from runner import NMAP_TIMEOUT_SECONDS, start_nmap
from parser import parse_xml
from history import save_job, load_job
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")
MAX_CONSECUTIVE_CONN_ERRORS = 3  # tras estos fallos de conexión seguidos se aborta el envío


def _persist(job):
    """Guarda el escaneo en el historial sin romper el flujo si falla."""
    try:
        save_job(job)
    except Exception:
        logger.exception("No se pudo guardar el escaneo %s en el historial", job.get("scan_id"))


def publish_events_to_siem(events, scan_id=None):
    """Envía cada evento individualmente mediante POST /events hacia el SIEM,
    comprueba el acuse y registra los fallos en el log.

    Devuelve solo un resumen (sin detalle por evento): el detalle de los
    errores es un asunto operativo y queda en los logs, no en la API.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    delivered = 0
    consecutive_conn_errors = 0

    for event in events:
        sent_event_id = event.get("event_id")
        try:
            response = requests.post(
                SIEM_URL,
                json=event,
                headers=headers,
                timeout=3,
            )
            consecutive_conn_errors = 0  # hubo conexión con el SIEM

            if response.status_code != 200:
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
                logger.warning(
                    "Acuse del SIEM no es JSON válido (scan_id=%s, event_id=%s)",
                    scan_id,
                    sent_event_id,
                )
                continue

            if not isinstance(ack, dict):
                logger.warning(
                    "Acuse del SIEM no es un objeto JSON (scan_id=%s, event_id=%s)",
                    scan_id,
                    sent_event_id,
                )
                continue

            if ack.get("status") != "success":
                logger.warning(
                    "Acuse del SIEM con status no válido (scan_id=%s, event_id=%s, status=%s)",
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
            consecutive_conn_errors += 1
            logger.warning(
                "Error al publicar evento en SIEM (scan_id=%s, event_id=%s): %s",
                scan_id,
                sent_event_id,
                exc,
            )
            if consecutive_conn_errors >= MAX_CONSECUTIVE_CONN_ERRORS:
                logger.error(
                    "SIEM inaccesible tras %d fallos de conexión seguidos; "
                    "se aborta el envío (scan_id=%s)",
                    consecutive_conn_errors,
                    scan_id,
                )
                break

    total = len(events)
    failed = total - delivered  # incluye los eventos no intentados tras abortar

    if total == 0:
        delivery_status = "not_required"
    elif failed == 0:
        delivery_status = "delivered"
    elif delivered == 0:
        delivery_status = "failed"
    else:
        delivery_status = "partial"

    if failed:
        logger.error(
            "Entrega al SIEM incompleta (scan_id=%s): %d/%d eventos sin entregar",
            scan_id,
            failed,
            total,
        )

    return {
        "status": delivery_status,
        "total": total,
        "delivered": delivered,
        "failed": failed,
    }


def _run_job_worker(job, xml_outfile):
    """Ejecuta el escaneo. `job` es una copia privada de este hilo."""
    scan_id = job["scan_id"]
    try:
        try:
            process = start_nmap(job["target"], job["profile"], xml_outfile)
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

        job["events"] = parse_xml(xml_content, scan_id, job["profile"])
        publish_events_to_siem(job["events"], scan_id=scan_id)
        job["status"] = "completed"
        _persist(job)

    except Exception as error:
        job["status"] = "failed"
        # No se devuelve stderr ni detalles del entorno a los consumidores de la API.
        if isinstance(error, (RuntimeError, ParseError)):
            message = str(error)
        else:
            logger.exception("Error interno en el escaneo %s", scan_id)
            message = "Error interno al ejecutar o procesar Nmap"
        job["error"] = message or "Error al ejecutar o procesar Nmap"
        _persist(job)
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
        "events": [],
    }
    _persist(job)

    # El hilo recibe su propia copia: no comparte estado con quien lo creó.
    t = threading.Thread(target=_run_job_worker, args=(dict(job), xml_outfile))
    t.daemon = True
    t.start()

    return job


def get_job(scan_id):
    """Lee el escaneo del historial (fuente de verdad)."""
    try:
        return load_job(scan_id)
    except Exception:
        logger.exception("No se pudo leer el escaneo %s del historial", scan_id)
        return None


def public(job):
    if job is None:
        return None
    result = {
        "scan_id": job["scan_id"],
        "created_at": job.get("created_at"),
        "target": job["target"],
        "profile": job["profile"],
        "status": job["status"],
        "events": job.get("events", []),
    }
    
    if job.get("status") == "failed":
        result["error"] = job.get("error", "El escaneo ha fallado")
    return result
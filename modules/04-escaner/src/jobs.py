import uuid
import tempfile
import os
import requests
import threading
import subprocess
from xml.etree.ElementTree import ParseError
from runner import NMAP_TIMEOUT_SECONDS, start_nmap
from parser import parse_xml
from history import save_job, load_job, record_event_delivery, get_pending_events
from datetime import datetime, timezone
import logging
import time

logger = logging.getLogger(__name__)

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")
MAX_CONSECUTIVE_CONN_ERRORS = 3  # tras estos fallos de conexión seguidos se aborta el envío

_TOKEN = None
_TOKEN_OBTAINED_AT = 0.0
_TOKEN_LOCK = threading.Lock()
TOKEN_REFRESH_SECONDS = int(os.environ.get("SIEM_TOKEN_REFRESH_SECONDS", "1500"))

MAX_TRANSIENT_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.2
_RATE_LIMITED_UNTIL = 0.0

class RateLimitError(RuntimeError):
    def __init__(self, retry_after):
        super().__init__(f"Login limitado por 429; reintentar tras {retry_after}s")
        self.retry_after = retry_after


def _parse_retry_after(resp):
    raw = resp.headers.get("Retry-After", "60")
    try:
        return max(1.0, float(raw))
    except (TypeError, ValueError):
        return 60.0

    
def _login_url():
    identity_url = os.environ.get("IDENTITY_URL", "http://localhost:8001").rstrip("/")
    if identity_url.endswith("/auth/login"):
        return identity_url
    return f"{identity_url}/auth/login"


def get_token(force=False):
    global _TOKEN, _TOKEN_OBTAINED_AT, _RATE_LIMITED_UNTIL
    with _TOKEN_LOCK:
        now = time.monotonic()
        if now < _RATE_LIMITED_UNTIL:
            remaining = round(_RATE_LIMITED_UNTIL - now, 2)
            raise RateLimitError(remaining)
        if (
            not force
            and _TOKEN
            and (now - _TOKEN_OBTAINED_AT) < TOKEN_REFRESH_SECONDS
        ):
            return _TOKEN
        
        password = (
            os.environ.get("SIEM_SVC_PASSWORD")
            or os.environ.get("SERVICE_PASSWORD_ESCANER")
            or ""
        )

        resp = requests.post(
            _login_url(),
            json={
                "username": os.environ.get("SIEM_SVC_USER", "svc-escaner"),
                "password": password,
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=3,
        )
        if resp.status_code == 429:
            retry_after = _parse_retry_after(resp)
            _RATE_LIMITED_UNTIL = time.monotonic() + retry_after
            logger.warning(
                "G1 devolvió 429 en /auth/login; respetando Retry-After=%ss",
                retry_after,
            )
            raise RateLimitError(retry_after)
        resp.raise_for_status()
        token = resp.json().get("token")
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("Respuesta de /auth/login sin token válido")

        _TOKEN = token
        _TOKEN_OBTAINED_AT = now
        return _TOKEN

    
def _persist(job):
    """Guarda el escaneo en el historial sin romper el flujo si falla."""
    try:
        save_job(job)
    except Exception:
        logger.exception("No se pudo guardar el escaneo %s en el historial", job.get("scan_id"))


def _publish_single_event(event, token, base_headers, scan_id):
    """Envía un único evento gestionando 401 (1 reintento), 503/timeout (backoff) y 409."""
    sent_event_id = event.get("event_id")
    retried_401 = False

    for attempt in range(MAX_TRANSIENT_RETRIES + 1):
        try:
            response = _post_event(event, token, base_headers)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "Error/timeout al publicar evento en SIEM (scan_id=%s, event_id=%s, intento=%d): %s",
                scan_id,
                sent_event_id,
                attempt + 1,
                exc,
            )
            if attempt < MAX_TRANSIENT_RETRIES:
                time.sleep(BACKOFF_BASE_SECONDS * (2 ** attempt))
                continue
            return "pending", True

        status = response.status_code

        if status == 401 and not retried_401:
            retried_401 = True
            logger.warning(
                "SIEM respondió 401; renovando token y reintentando una vez "
                "(scan_id=%s, event_id=%s)",
                scan_id,
                sent_event_id,
            )
            try:
                token = get_token(force=True)
                continue
            except Exception as exc:
                logger.warning(
                    "Fallo al renovar token tras 401; evento queda pendiente "
                    "(scan_id=%s, event_id=%s): %s",
                    scan_id,
                    sent_event_id,
                    exc,
                )
                return "pending", False

        if status == 409:
            logger.warning(
                "Rechazo definitivo 409 EVENT_ID_CONFLICT en SIEM; no se reintenta "
                "(scan_id=%s, event_id=%s)",
                scan_id,
                sent_event_id,
            )
            return "rejected_conflict", False

        if status == 503:
            logger.warning(
                "SIEM no disponible (503) al publicar evento (scan_id=%s, event_id=%s, intento=%d)",
                scan_id,
                sent_event_id,
                attempt + 1,
            )
            if attempt < MAX_TRANSIENT_RETRIES:
                time.sleep(BACKOFF_BASE_SECONDS * (2 ** attempt))
                continue
            return "pending", False

        if status != 200:
            logger.warning(
                "Fallo al publicar evento en SIEM (scan_id=%s, event_id=%s, status=%s)",
                scan_id,
                sent_event_id,
                status,
            )
            return "rejected", False

        try:
            ack = response.json()
        except ValueError:
            logger.warning(
                "Acuse del SIEM no es JSON válido (scan_id=%s, event_id=%s)",
                scan_id,
                sent_event_id,
            )
            return "pending", False

        if not isinstance(ack, dict):
            logger.warning(
                "Acuse del SIEM no es un objeto JSON (scan_id=%s, event_id=%s)",
                scan_id,
                sent_event_id,
            )
            return "pending", False

        if ack.get("status") != "success":
            logger.warning(
                "Acuse del SIEM con status no válido (scan_id=%s, event_id=%s, status=%s)",
                scan_id,
                sent_event_id,
                ack.get("status"),
            )
            return "pending", False

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
            return "pending", False

        return "delivered", False

    return "pending", False


def publish_events_to_siem(events, scan_id=None):
    """Envía cada evento individualmente mediante POST /events hacia el SIEM,
    comprueba el acuse y registra los fallos en el log.

    Devuelve solo un resumen (sin detalle por evento): el detalle de los
    errores es un asunto operativo y queda en los logs, no en la API.
    """
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    delivered = 0
    consecutive_conn_errors = 0

    for event in events:
        sent_event_id = event.get("event_id")
        try:
            token = get_token()
        except Exception as exc:
            logger.warning(
                "No se pudo obtener token de servicio para publicar en SIEM "
                "(scan_id=%s, event_id=%s): %s",
                scan_id,
                sent_event_id,
                exc,
            )
            record_event_delivery(event, "pending", scan_id=scan_id)
            continue

        outcome, conn_error = _publish_single_event(event, token, base_headers, scan_id)
        record_event_delivery(event, outcome, scan_id=scan_id)

        if outcome == "delivered":
            delivered += 1
            consecutive_conn_errors = 0
            continue

        if conn_error:
            consecutive_conn_errors += 1
            if consecutive_conn_errors >= MAX_CONSECUTIVE_CONN_ERRORS:
                logger.error(
                    "SIEM inaccesible tras %d fallos de conexión seguidos; "
                    "se aborta el envío (scan_id=%s)",
                    consecutive_conn_errors,
                    scan_id,
                )
                break
        else:
            consecutive_conn_errors = 0

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


def retry_pending_events(limit=None): 
    """Reintenta los eventos marcados como 'pending' conservando su contenido."""
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    pending = get_pending_events(limit=limit)
    delivered = 0
    still_pending = 0
    rejected_conflict = 0

    for scan_id, event in pending:
        try:
            token = get_token()
        except Exception as exc:
            logger.warning(
                "No se pudo obtener token al reintentar pendiente "
                "(scan_id=%s, event_id=%s): %s",
                scan_id,
                event.get("event_id"),
                exc,
            )
            record_event_delivery(event, "pending", scan_id=scan_id)
            still_pending += 1
            continue

        outcome, _ = _publish_single_event(event, token, base_headers, scan_id)
        record_event_delivery(event, outcome, scan_id=scan_id)
        if outcome == "delivered":
            delivered += 1
        elif outcome == "rejected_conflict":
            rejected_conflict += 1
        else:
            still_pending += 1

    return {
        "total": len(pending),
        "delivered": delivered,
        "pending": still_pending,
        "rejected_conflict": rejected_conflict,
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


def _post_event(event: dict, token: str, headers_base: dict) -> requests.Response:
    headers = {
        **headers_base,
        "Authorization": f"Bearer {token}",
    }
    return requests.post(
        SIEM_URL,
        json=event,
        headers=headers,
        timeout=3,
    )
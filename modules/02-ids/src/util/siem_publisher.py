import copy
import json
import logging
import os
import time
from pathlib import Path

import requests


logger = logging.getLogger(__name__)

PUBLISH_SENT = "sent"
PUBLISH_PERMANENT_REJECT = "permanent_reject"
PUBLISH_TEMPORARY_FAILURE = "temporary_failure"
PUBLISH_AUTHENTICATION_FAILURE = "authentication_failure"

IDENTITY_TOKEN_LIFETIME_SECONDS = 30 * 60
IDENTITY_TOKEN_REFRESH_MARGIN_SECONDS = 2 * 60


class IdentityAuthenticationError(RuntimeError):
    """G1 no pudo emitir un token para el IDS."""


class IdentityTokenProvider:
    def __init__(
        self,
        identity_url=None,
        username=None,
        password=None,
        session=None,
        clock=None,
    ):
        self.identity_url = (
            identity_url or os.getenv("IDENTIDAD_URL", "http://identidad:80")
        ).rstrip("/")
        self.username = username or os.getenv("IDS_SERVICE_USERNAME", "servicio")
        self.password = (
            password if password is not None else os.getenv("IDS_SERVICE_PASSWORD")
        )
        self.session = session if session is not None else requests
        self.clock = clock if clock is not None else time.monotonic
        self._token = None
        self._expires_at = 0

    def get_token(self, timeout=5):
        if (
            self._token
            and self.clock()
            < self._expires_at - IDENTITY_TOKEN_REFRESH_MARGIN_SECONDS
        ):
            return self._token

        if not self.username or not self.password:
            logger.error(
                "No se puede autenticar el IDS en G1: faltan las credenciales "
                "de la cuenta de servicio."
            )
            raise IdentityAuthenticationError("Faltan credenciales de G1.")

        login_url = f"{self.identity_url}/auth/login"
        try:
            response = self.session.post(
                login_url,
                json={"username": self.username, "password": self.password},
                timeout=timeout,
            )
        except (requests.RequestException, TimeoutError, ConnectionError) as error:
            logger.error("No se pudo iniciar sesión en G1: %s", error)
            self.invalidate()
            raise IdentityAuthenticationError("No se pudo iniciar sesión en G1.") from error

        try:
            token = response.json().get("token")
        except (ValueError, AttributeError):
            token = None

        if response.status_code != 200 or not isinstance(token, str) or not token:
            logger.error(
                "G1 rechazó o no completó el login del IDS (HTTP %s).",
                response.status_code,
            )
            self.invalidate()
            raise IdentityAuthenticationError("G1 no devolvió un token válido.")

        self._token = token
        self._expires_at = self.clock() + IDENTITY_TOKEN_LIFETIME_SECONDS
        return self._token

    def invalidate(self, token=None):
        if token is None or token == self._token:
            self._token = None
            self._expires_at = 0


_default_token_provider = IdentityTokenProvider()


def get_siem_url():
    return os.getenv("SIEM_URL", "http://siem:80/events").strip()


def get_pending_path():
    return Path(__file__).resolve().parents[2] / "output" / "pending_events.json"


def load_pending(path=None):
    path = Path(path) if path is not None else get_pending_path()
    try:
        with path.open(encoding="utf-8") as file:
            pending = json.load(file)
        return pending if isinstance(pending, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def save_pending(pending, path=None):
    path = Path(path) if path is not None else get_pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(pending, file, ensure_ascii=False, indent=2)


def publish_event(
    event, siem_url=None, timeout=5, session=None, token_provider=None
):
    payload = copy.deepcopy(event)
    url = siem_url or get_siem_url()
    http = session or requests
    auth = token_provider if token_provider is not None else _default_token_provider

    try:
        token = auth.get_token(timeout=timeout)
    except IdentityAuthenticationError:
        return PUBLISH_AUTHENTICATION_FAILURE

    def send_event(bearer_token):
        try:
            return http.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {bearer_token}"},
                timeout=timeout,
            )
        except (requests.RequestException, TimeoutError, ConnectionError) as error:
            logger.warning(
                "No se pudo publicar el evento %s: %s", payload["event_id"], error
            )
            return None

    response = send_event(token)
    if response is None:
        return PUBLISH_TEMPORARY_FAILURE

    if response.status_code == 401:
        auth.invalidate(token)
        try:
            renewed_token = auth.get_token(timeout=timeout)
        except IdentityAuthenticationError:
            return PUBLISH_AUTHENTICATION_FAILURE

        response = send_event(renewed_token)
        if response is None:
            return PUBLISH_TEMPORARY_FAILURE
        if response.status_code == 401:
            logger.error(
                "El SIEM volvió a responder 401 para el evento %s tras renovar "
                "el token; se reintentará desde la cola.",
                payload["event_id"],
            )
            return PUBLISH_AUTHENTICATION_FAILURE

    if response.status_code == 200:
        try:
            acknowledged_id = response.json().get("event_id")
        except (ValueError, AttributeError):
            acknowledged_id = None
        if acknowledged_id != payload["event_id"]:
            logger.error(
                "El SIEM respondió 200 sin confirmar el event_id enviado: "
                "enviado=%s, recibido=%s",
                payload["event_id"],
                acknowledged_id,
            )
            return PUBLISH_TEMPORARY_FAILURE
        return PUBLISH_SENT

    detail = getattr(response, "text", "") or ""
    if response.status_code == 409:
        logger.error(
            "Rechazo definitivo del evento %s: HTTP 409 EVENT_ID_CONFLICT. Detalle: %s",
            payload["event_id"],
            detail[:500],
        )
        return PUBLISH_PERMANENT_REJECT

    logger.warning(
        "El SIEM rechazó el evento %s con HTTP %s: %s",
        payload["event_id"],
        response.status_code,
        detail[:500],
    )
    if 500 <= response.status_code <= 599:
        return PUBLISH_TEMPORARY_FAILURE
    return PUBLISH_PERMANENT_REJECT


def publish_and_queue_status(
    event,
    siem_url=None,
    timeout=5,
    session=None,
    pending_path=None,
    retries=2,
    retry_delay=1,
    token_provider=None,
):
    pending_path = Path(pending_path) if pending_path is not None else get_pending_path()

    pending = load_pending(pending_path)
    payload = copy.deepcopy(event)

    for attempt in range(retries + 1):
        result = publish_event(
            payload,
            siem_url=siem_url,
            timeout=timeout,
            session=session,
            token_provider=token_provider,
        )
        if result == PUBLISH_AUTHENTICATION_FAILURE:
            result = PUBLISH_TEMPORARY_FAILURE
            break
        if result == PUBLISH_SENT:
            remaining = [
                pending_event
                for pending_event in pending
                if not (
                    isinstance(pending_event, dict)
                    and pending_event.get("event_id") == payload["event_id"]
                )
            ]
            save_pending(remaining, pending_path)
            return PUBLISH_SENT
        if result == PUBLISH_PERMANENT_REJECT:
            remaining = [
                pending_event
                for pending_event in pending
                if not (
                    isinstance(pending_event, dict)
                    and pending_event.get("event_id") == payload["event_id"]
                )
            ]
            save_pending(remaining, pending_path)
            return PUBLISH_PERMANENT_REJECT
        if attempt < retries:
            time.sleep(retry_delay)

    existing_ids = {
        pending_event.get("event_id")
        for pending_event in pending
        if isinstance(pending_event, dict)
    }
    if payload["event_id"] not in existing_ids:
        pending.append(copy.deepcopy(payload))
        save_pending(pending, pending_path)

    return PUBLISH_TEMPORARY_FAILURE


def publish_and_queue(
    event,
    siem_url=None,
    timeout=5,
    session=None,
    pending_path=None,
    retries=2,
    retry_delay=1,
    token_provider=None,
):
    result = publish_and_queue_status(
        event,
        siem_url=siem_url,
        timeout=timeout,
        session=session,
        pending_path=pending_path,
        retries=retries,
        retry_delay=retry_delay,
        token_provider=token_provider,
    )
    return result == PUBLISH_SENT


def retry_pending(
    siem_url=None,
    timeout=5,
    session=None,
    pending_path=None,
    retries=0,
    retry_delay=1,
    token_provider=None,
):
    pending_path = Path(pending_path) if pending_path is not None else get_pending_path()
    pending = load_pending(pending_path)
    remaining = []

    for event in pending:
        if not isinstance(event, dict):
            continue
        result = publish_and_queue_status(
            event,
            siem_url=siem_url,
            timeout=timeout,
            session=session,
            pending_path=pending_path,
            retries=retries,
            retry_delay=retry_delay,
            token_provider=token_provider,
        )
        if result == PUBLISH_TEMPORARY_FAILURE:
            remaining.append(copy.deepcopy(event))

    save_pending(remaining, pending_path)

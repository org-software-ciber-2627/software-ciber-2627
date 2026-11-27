import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from soar.models.playbook import (
    BRUTE_FORCE_ACTIONS,
    ActionResult,
    BruteForcePlaybookInput,
    BruteForcePlaybookOutput,
    playbook_status,
)
from soar.services.blacklist_service import (
    ALREADY_BLOCKED,
    BLOCKED,
    EXCLUDED,
    INVALID_IP,
    BlacklistService,
)

# HU19.2: resultado de la lista negra → estado de la acción block_ip
BLOCK_IP_STATUSES = {
    BLOCKED: "success",
    ALREADY_BLOCKED: "success",
    EXCLUDED: "skipped",
    INVALID_IP: "failed",
}

NOTIFY_TIMEOUT_SECONDS = 5
NOTIFY_TARGET = "group7"

HttpPost = Callable[[str, dict[str, Any], float], int]


def post_json(url: str, payload: dict[str, Any], timeout: float) -> int:
    """
    Envía un POST JSON con urllib y devuelve el código HTTP.
    urllib lanza HTTPError para los códigos >= 400.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status


class PlaybookService:

    def __init__(
        self,
        notify_url: Optional[str] = None,
        http_post: HttpPost = post_json,
        clock: Optional[Callable[[], datetime]] = None,
        blacklist_service: Optional[BlacklistService] = None,
    ) -> None:
        # Si no se indica, la URL del grupo 7 sale de GROUP7_NOTIFY_URL
        self._notify_url = notify_url if notify_url is not None else os.getenv("GROUP7_NOTIFY_URL", "")
        self._http_post = http_post
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        # Sin lista negra, block_ip se omite (skipped); la conexión con SQLite llega en HU19.3
        self._blacklist = blacklist_service

    def execute_brute_force_playbook(
        self,
        playbook_input: BruteForcePlaybookInput,
        reason: str = "",
    ) -> BruteForcePlaybookOutput:
        """
        Ejecuta en orden las acciones del playbook de fuerza bruta del Sprint actual.
        """
        executed_at = self._clock()
        actions = [self._run_action(name, playbook_input, reason) for name in BRUTE_FORCE_ACTIONS]
        status = playbook_status(actions)

        return BruteForcePlaybookOutput(
            execution_id=str(uuid4()),
            incident_id=playbook_input.incident_id,
            status=status,
            actions_taken=actions,
            executed_at=executed_at,
            summary=", ".join(f"{action.action_name}={action.status}" for action in actions),
        )

    def _run_action(self, name: str, playbook_input: BruteForcePlaybookInput, reason: str) -> ActionResult:
        if name == "block_ip":
            return self._block_ip(playbook_input, reason)
        if name == "notify":
            return self._notify(playbook_input, reason)
        return ActionResult(
            action_name=name, target=playbook_input.source_ip, status="skipped",
            details="Acción no implementada en este Sprint",
        )

    def _block_ip(self, playbook_input: BruteForcePlaybookInput, reason: str) -> ActionResult:
        """
        HU19.2: mete la IP atacante en la lista negra simulada del SOAR.
        Un error de la lista negra no detiene el playbook: block_ip queda en failed y se sigue con notify.
        """
        target = playbook_input.source_ip
        if self._blacklist is None:
            return ActionResult(
                action_name="block_ip", target=target, status="skipped",
                details="Lista negra no configurada",
            )
        try:
            result = self._blacklist.block(target, playbook_input.incident_id, reason)
        except Exception as error:
            return ActionResult(
                action_name="block_ip", target=target, status="failed",
                details=f"No se pudo bloquear la IP: {error}",
            )

        if result.outcome == ALREADY_BLOCKED:
            details = f"{result.message}: la IP ya está contenida"
        elif result.outcome == EXCLUDED:
            details = f"{result.message}: es una IP protegida"
        else:
            details = result.message
        return ActionResult(
            action_name="block_ip", target=target, status=BLOCK_IP_STATUSES[result.outcome], details=details,
        )

    def _notify(self, playbook_input: BruteForcePlaybookInput, reason: str) -> ActionResult:
        """
        Envía el incidente al grupo 7 (dashboard) por HTTP POST.
        """
        if not self._notify_url:
            return ActionResult(
                action_name="notify", target=NOTIFY_TARGET, status="skipped",
                details="GROUP7_NOTIFY_URL no está configurada",
            )

        # Fuera de este sprint: el grupo 7 no tiene receptor; sin GROUP7_NOTIFY_URL la acción queda en skipped
        payload = {
            "incident_id": playbook_input.incident_id,
            "event_type": playbook_input.event_type,
            "severity": playbook_input.severity,
            "priority": playbook_input.priority,
            "source_ip": playbook_input.source_ip,
            "service": playbook_input.service,
            "username": playbook_input.username,
            "usernames": playbook_input.usernames,
            "failed_attempts": playbook_input.failed_attempts,
            "playbook": "brute_force",
            "reason": reason,
            "detected_at": playbook_input.detected_at,
        }
        try:
            status_code = self._http_post(self._notify_url, payload, NOTIFY_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            return ActionResult(
                action_name="notify", target=NOTIFY_TARGET, status="failed",
                details=f"El grupo 7 respondió HTTP {error.code}",
            )
        except (OSError, ValueError) as error:
            # URLError, TimeoutError y errores de socket heredan de OSError; ValueError cubre URLs mal formadas
            return ActionResult(
                action_name="notify", target=NOTIFY_TARGET, status="failed",
                details=f"No se pudo notificar al grupo 7: {error}",
            )

        if status_code >= 400:
            return ActionResult(
                action_name="notify", target=NOTIFY_TARGET, status="failed",
                details=f"El grupo 7 respondió HTTP {status_code}",
            )
        return ActionResult(
            action_name="notify", target=NOTIFY_TARGET, status="success",
            details=f"Incidente notificado al grupo 7 (HTTP {status_code})",
        )

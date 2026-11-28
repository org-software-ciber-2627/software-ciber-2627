from datetime import timezone

from soar.models.executed_response import ExecutedResponse
from soar.models.playbook import BruteForcePlaybookOutput


def responses_from_playbook_output(
    output: BruteForcePlaybookOutput,
    triggered_by: str = "automatic",
) -> list[ExecutedResponse]:
    """
    Convierte la salida de un playbook (HU14) en una respuesta ejecutada (HU15) por acción.
    No modifica la salida recibida.
    """
    executed_at = output.executed_at
    if executed_at.tzinfo is None:
        executed_at = executed_at.replace(tzinfo=timezone.utc)
    executed_at = executed_at.astimezone(timezone.utc)

    return [
        ExecutedResponse(
            incident_id=output.incident_id,
            playbook=output.playbook,
            action=action.action_name,
            status=action.status,
            triggered_by=triggered_by,
            executed_at=executed_at,
            message=action.details if action.status == "success" else None,
            error=action.details if action.status != "success" else None,
            details={
                "target": action.target,
                "execution_id": output.execution_id,
                "playbook_status": output.status,
            },
        )
        for action in output.actions_taken
    ]

from soar.models.automation_decision import AutomationDecision
from soar.models.incident import Incident


AUTOMATABLE_PLAYBOOKS = {
    "fuerza_bruta": "brute_force",
}


def evaluate_automation(incident: Incident) -> AutomationDecision:
    playbook = AUTOMATABLE_PLAYBOOKS.get(incident.event_type)

    if playbook is None:
        return AutomationDecision(
            automatable=False,
            playbook=None,
            reason=f"No existe un playbook para el tipo de evento '{incident.event_type}'",
        )

    if not incident.source_ip:
        return AutomationDecision(
            automatable=False,
            playbook=None,
            reason="El incidente no contiene una IP de origen",
        )

    return AutomationDecision(
        automatable=True,
        playbook=playbook,
        reason="Incidente compatible con automatizacion",
    )

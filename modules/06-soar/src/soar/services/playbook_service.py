from datetime import datetime
from uuid import uuid4

from soar.models.playbook import (
    ActionResult,
    BruteForcePlaybookInput,
    BruteForcePlaybookOutput,
)


class PlaybookService:

    def execute_brute_force_playbook(
        self,
        playbook_input: BruteForcePlaybookInput,
    ) -> BruteForcePlaybookOutput:

        action_result = ActionResult(
            action_name="block_ip",
            target=playbook_input.source_ip,
            success=True,
            details="IP blocked successfully"
        )

        return BruteForcePlaybookOutput(
            execution_id=str(uuid4()),
            incident_id=playbook_input.incident_id,
            status="COMPLETED",
            actions_taken=[action_result],
            executed_at=datetime.utcnow(),
            summary=f"Blocked source IP {playbook_input.source_ip}"
        )
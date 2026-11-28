import unittest
from datetime import datetime, timezone

from soar.models.playbook import ActionResult, BruteForcePlaybookOutput
from soar.services.response_mapper import responses_from_playbook_output


EXECUTED_AT = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def build_output(*actions, status="PARTIAL"):
    return BruteForcePlaybookOutput(
        execution_id="exec-1",
        incident_id="INC-001",
        status=status,
        actions_taken=list(actions),
        executed_at=EXECUTED_AT,
        summary="",
    )


class TestResponseMapper(unittest.TestCase):
    def test_one_response_per_action(self):
        output = build_output(
            ActionResult(action_name="notify", target="group7", status="success", details="Notificado"),
            ActionResult(action_name="block_ip", target="192.168.1.50", status="failed", details="Timeout"),
        )

        responses = responses_from_playbook_output(output)

        self.assertEqual([r.action for r in responses], ["notify", "block_ip"])
        self.assertTrue(all(r.incident_id == "INC-001" for r in responses))
        self.assertTrue(all(r.playbook == "brute_force" for r in responses))
        self.assertTrue(all(r.triggered_by == "automatic" for r in responses))

    def test_success_uses_message_and_failures_use_error(self):
        output = build_output(
            ActionResult(action_name="notify", target="group7", status="success", details="Notificado"),
            ActionResult(action_name="block_ip", target="1.2.3.4", status="failed", details="Timeout"),
            ActionResult(action_name="disable_account", target="root", status="skipped", details="Sprint 3"),
        )

        success, failed, skipped = responses_from_playbook_output(output)

        self.assertEqual((success.status, success.message, success.error), ("success", "Notificado", None))
        self.assertEqual((failed.status, failed.message, failed.error), ("failed", None, "Timeout"))
        self.assertEqual((skipped.status, skipped.message, skipped.error), ("skipped", None, "Sprint 3"))

    def test_details_and_dates(self):
        output = build_output(
            ActionResult(action_name="notify", target="group7", status="success", details="ok"),
            status="COMPLETED",
        )

        response = responses_from_playbook_output(output, triggered_by="manual")[0]

        self.assertEqual(response.details, {"target": "group7", "execution_id": "exec-1", "playbook_status": "COMPLETED"})
        self.assertEqual(response.executed_at, EXECUTED_AT)
        self.assertEqual(response.executed_at.utcoffset().total_seconds(), 0)
        self.assertEqual(response.triggered_by, "manual")

    def test_output_without_actions_returns_empty_list(self):
        self.assertEqual(responses_from_playbook_output(build_output(status="FAILED")), [])

    def test_mapping_does_not_modify_output(self):
        output = build_output(
            ActionResult(action_name="notify", target="group7", status="success", details="ok"),
            status="COMPLETED",
        )
        snapshot = output.model_dump()

        responses_from_playbook_output(output)

        self.assertEqual(output.model_dump(), snapshot)


if __name__ == "__main__":
    unittest.main()

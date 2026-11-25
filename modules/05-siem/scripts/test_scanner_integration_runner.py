"""Regression checks for safe failure handling in the real integration runner."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("scanner_integration_runner", Path(__file__).with_name("test-scanner-integration.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ScannerIntegrationRunnerTests(unittest.TestCase):
    def test_invalid_arguments_invalidate_previous_success(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            for arguments, error in [(["--scan-timeout", "1"], RuntimeError), (["--unknown"], SystemExit)]:
                report.write_text('{"status":"passed"}')
                with patch.object(runner, "REPORT", report), patch.object(sys, "argv", ["runner", *arguments]):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(error):
                        runner.main()
                self.assertFalse(report.exists())

    def test_timeout_does_not_expose_command_arguments(self):
        command = ["docker", "run", "-e", "POSTGRES_PASSWORD=SECRET_TOKEN"]
        with patch.object(runner.subprocess, "run", side_effect=subprocess.TimeoutExpired(command, 1)):
            with self.assertRaises(RuntimeError) as captured:
                runner.command_run(command, {})
        self.assertNotIn("SECRET_TOKEN", str(captured.exception))
        self.assertTrue(captured.exception.__suppress_context__)

    def test_daemon_failure_is_not_resource_absence(self):
        def failed(*command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", "Cannot connect to the Docker daemon")
        errors = runner.cleanup_resources(failed, ["test-container"], "test-network", ["test-image"])
        self.assertEqual(len(errors), 3)

    def test_cleanup_continues_after_a_resource_timeout(self):
        attempted = []
        def command(*arguments, **kwargs):
            attempted.append(arguments)
            if "test-container" in arguments:
                raise RuntimeError("Command timed out: docker")
            return subprocess.CompletedProcess(arguments, 0, "", "")
        errors = runner.cleanup_resources(command, ["test-container"], "test-network", ["test-image"])
        self.assertEqual(len(errors), 1)
        self.assertTrue(any(arguments[1:3] == ("network", "rm") for arguments in attempted))
        self.assertTrue(any(arguments[1:3] == ("image", "rm") for arguments in attempted))

    def test_known_missing_resource_is_not_a_cleanup_failure(self):
        def missing(*command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", "Error: No such object: " + command[-1])
        self.assertEqual(runner.cleanup_resources(missing, ["test-container"], "test-network", ["test-image"]), [])


if __name__ == "__main__":
    unittest.main()

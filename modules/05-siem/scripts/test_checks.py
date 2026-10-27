"""Regression checks for verification scripts without Docker or network access."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest


SCRIPTS = Path(__file__).resolve().parent


class VerificationScriptTests(unittest.TestCase):
    def test_optimized_smoke_rejects_http_failures(self):
        program = """
import io
import runpy
import sys
from unittest.mock import patch

class FailedResponse(io.BytesIO):
    status = 500

def failed_response(*args, **kwargs):
    return FailedResponse(b'{}')

script = sys.argv[1]
sys.argv = [script, 'http://127.0.0.1:1']
with patch('urllib.request.urlopen', failed_response):
    runpy.run_path(script, run_name='__main__')
"""
        result = subprocess.run([sys.executable, "-O", "-c", program, str(SCRIPTS / "smoke-test.py")],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("health identifies 05-siem", result.stderr)
        self.assertNotIn('"result": "PASS"', result.stdout)

    def test_contract_verifier_rejects_disabled_assertions(self):
        result = subprocess.run([sys.executable, "-O", str(SCRIPTS / "verify-contract.py")],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("Run without Python optimization", result.stderr)

    def test_rejected_storage_invocations_remove_stale_success_reports(self):
        for arguments in (("-O",), ("invalid",)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as directory:
                module = Path(directory) / "modules/05-siem"
                script = module / "scripts/test-storage.py"
                script.parent.mkdir(parents=True)
                shutil.copyfile(SCRIPTS / "test-storage.py", script)
                report = module / "target/sem66/report.json"
                report.parent.mkdir(parents=True)
                report.write_text('{"status":"passed"}')
                command = [sys.executable, "-O", str(script)] if arguments == ("-O",) else [sys.executable, str(script), "--invalid"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(report.exists(), "A failed run left a stale success report")


if __name__ == "__main__":
    unittest.main()

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from jobs import JOBS, _run_job_worker, public
from main import app


class FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode

    def communicate(self, timeout=None):
        return "", ""

    def kill(self):
        self.returncode = -9


class TimeoutProcess(FakeProcess):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def communicate(self, timeout=None):
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired("nmap", timeout)
        return "", ""


class TestScannerFlow(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.jobs_patch = patch.dict(JOBS, {}, clear=True)
        self.jobs_patch.start()
        self.addCleanup(self.jobs_patch.stop)

    def test_api_conecta_perfil_elegido_con_trabajo(self):
        with patch("main.create_job", return_value={
            "scan_id": "scan-web", "target": "192.0.2.10", "profile": "web",
            "status": "running", "events": [],
        }) as create:
            response = self.client.post("/scan", json={"target": " 192.0.2.10 ", "profile": "web"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["profile"], "web")
        create.assert_called_once_with("192.0.2.10", "web")

    def test_falla_si_nmap_no_crea_xml_y_se_limipa_temporal(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
        JOBS["scan-fail"] = {
            "scan_id": "scan-fail", "target": "192.0.2.10", "profile": "vuln",
            "status": "running", "events": [],
        }
        with patch("jobs.start_nmap", return_value=FakeProcess()), \
             patch("jobs.publish_events_to_siem"):
            _run_job_worker("scan-fail", "192.0.2.10", "vuln", path)

        self.assertEqual(JOBS["scan-fail"]["status"], "failed")
        self.assertIn("informe XML", JOBS["scan-fail"]["error"])
        self.assertEqual(public(JOBS["scan-fail"])["error"], JOBS["scan-fail"]["error"])
        self.assertFalse(os.path.exists(path))

    def test_nmap_no_cero_falla_sin_publicar(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
            file.write(b"no debe procesarse")
        JOBS["scan-exit"] = {
            "scan_id": "scan-exit", "target": "192.0.2.10", "profile": "vuln",
            "status": "running", "events": [],
        }
        with patch("jobs.start_nmap", return_value=FakeProcess(returncode=2)), \
             patch("jobs.publish_events_to_siem") as publish:
            _run_job_worker("scan-exit", "192.0.2.10", "vuln", path)

        self.assertEqual(JOBS["scan-exit"]["status"], "failed")
        self.assertIn("código 2", JOBS["scan-exit"]["error"])
        publish.assert_not_called()
        self.assertFalse(os.path.exists(path))

    def test_informe_valido_se_normaliza_y_publica_al_siem(self):
        xml = '''<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4" />
        <ports><port protocol="tcp" portid="443"><state state="open" />
        <service name="https" /><script id="demo" output="VULNERABLE: ejemplo" />
        </port></ports></host></nmaprun>'''
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name

        def start_nmap(target, profile, outfile):
            with open(outfile, "w", encoding="utf-8") as output:
                output.write(xml)
            return FakeProcess()

        JOBS["scan-ok"] = {
            "scan_id": "scan-ok", "target": "192.0.2.10", "profile": "vuln",
            "status": "running", "events": [],
        }
        with patch("jobs.start_nmap", side_effect=start_nmap), \
             patch("jobs.publish_events_to_siem") as publish:
            _run_job_worker("scan-ok", "192.0.2.10", "vuln", path)

        job = JOBS["scan-ok"]
        self.assertEqual(job["status"], "completed")
        finding = next(event for event in job["events"]
                       if event["event_type"] == "vulnerability_detected")
        self.assertEqual(finding["source"], "scanner")
        self.assertEqual(finding["details"]["profile"], "vuln")
        self.assertEqual(finding["details"]["scan_id"], "scan-ok")
        publish.assert_called_once_with(job["events"])
        self.assertFalse(os.path.exists(path))

    def test_timeout_termina_proceso_y_marca_fallo(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
        process = TimeoutProcess()
        JOBS["scan-timeout"] = {
            "scan_id": "scan-timeout", "target": "192.0.2.10", "profile": "vuln",
            "status": "running", "events": [],
        }
        with patch("jobs.start_nmap", return_value=process), \
             patch("jobs.publish_events_to_siem"):
            _run_job_worker("scan-timeout", "192.0.2.10", "vuln", path)

        self.assertEqual(JOBS["scan-timeout"]["status"], "failed")
        self.assertIn("superó el límite", JOBS["scan-timeout"]["error"])
        self.assertEqual(process.returncode, -9)
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)

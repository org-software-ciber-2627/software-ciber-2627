import os
import subprocess
import tempfile
import requests
import unittest
from unittest.mock import Mock, patch

from jobs import JOBS, _run_job_worker, public, publish_events_to_siem
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
        publish.assert_called_once_with(job["events"], scan_id="scan-ok")
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

class TestSiemDelivery(unittest.TestCase):
    def test_acepta_acuse_correcto(self):
        event = {
            "event_id": "evt-001",
            "source": "scanner",
        }
        response = Mock(status_code=200)
        response.json.return_value = {
            "status": "success",
            "event_id": "evt-001",
        }

        with patch("jobs.requests.post", return_value=response) as post:
            result = publish_events_to_siem([event])

        post.assert_called_once()
        self.assertEqual(result, {
            "status": "delivered",
            "total": 1,
            "delivered": 1,
            "failed": 0,
            "errors": [],
        })

    def test_registra_error_http_del_siem(self):
        event = {
            "event_id": "evt-002",
            "source": "scanner",
        }
        response = Mock(status_code=400)
    
        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([event])
    
        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-002",
                "code": "http_error",
                "status_code": 400,
            }],
        })

    def test_registra_ack_no_json(self):
        event = {
            "event_id": "evt-003",
            "source": "scanner",
        }
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("respuesta no válida")

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([event])

        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-003",
                "code": "invalid_json_ack",
            }],
        })

    def test_registra_status_incorrecto_del_siem(self):
        event = {
            "event_id": "evt-004",
            "source": "scanner",
        }
        response = Mock(status_code=200)
        response.json.return_value = {
            "status": "error",
            "event_id": "evt-004",
        }

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([event])

        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-004",
                "code": "invalid_ack_status",
            }],
        })

    def test_registra_event_id_distinto(self):
        event = {
            "event_id": "evt-005",
            "source": "scanner",
        }
        response = Mock(status_code=200)
        response.json.return_value = {
            "status": "success",
            "event_id": "evt-otro",
        }

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([event])

        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-005",
                "code": "event_id_mismatch",
            }],
        })

    def test_registra_timeout_de_conexion(self):
        event = {
            "event_id": "evt-006",
            "source": "scanner",
        }

        with patch(
            "jobs.requests.post",
            side_effect=requests.exceptions.Timeout,
        ):
            result = publish_events_to_siem([event])

        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-006",
                "code": "connection_error",
                "error_type": "Timeout",
            }],
        })

    def test_registra_entrega_parcial(self):
        events = [
            {"event_id": "evt-007", "source": "scanner"},
            {"event_id": "evt-008", "source": "scanner"},
        ]

        ok_response = Mock(status_code=200)
        ok_response.json.return_value = {
            "status": "success",
            "event_id": "evt-007",
        }
        error_response = Mock(status_code=400)

        with patch(
            "jobs.requests.post",
            side_effect=[ok_response, error_response],
        ):
            result = publish_events_to_siem(events)

        self.assertEqual(result, {
            "status": "partial",
            "total": 2,
            "delivered": 1,
            "failed": 1,
            "errors": [{
                "event_id": "evt-008",
                "code": "http_error",
                "status_code": 400,
            }],
        })

    def test_registra_ack_que_no_es_objeto(self):
        event = {
            "event_id": "evt-009",
            "source": "scanner",
        }
        response = Mock(status_code=200)
        response.json.return_value = []

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([event])

        self.assertEqual(result, {
            "status": "failed",
            "total": 1,
            "delivered": 0,
            "failed": 1,
            "errors": [{
                "event_id": "evt-009",
                "code": "invalid_ack",
            }],
        })

    def test_sin_eventos_no_contacta_al_siem(self):
        with patch("jobs.requests.post") as post:
            result = publish_events_to_siem([])

        self.assertEqual(result, {
            "status": "not_required",
            "total": 0,
            "delivered": 0,
            "failed": 0,
            "errors": [],
        })
        post.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)

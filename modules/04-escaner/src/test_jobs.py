import os
import subprocess
import tempfile
import requests
import unittest
from unittest.mock import Mock, patch

from jobs import _run_job_worker, public, publish_events_to_siem
from main import app

# Identidad (G1) simulada: el token se da por válido con rol analista
IDENTIDAD_OK = {"valid": True, "user_id": 1, "username": "test", "role": "analista"}
CABECERA = {"Authorization": "Bearer token-de-prueba"}


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


def nuevo_job(scan_id):
    """El worker recibe el propio diccionario del escaneo y lo modifica."""
    return {"scan_id": scan_id, "target": "192.0.2.10", "profile": "vuln",
            "status": "running", "events": []}


class TestScannerFlow(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

        # El worker guarda en el historial: lo simulamos para no tocar ninguna BBDD
        save_patch = patch("jobs.save_job")
        save_patch.start()
        self.addCleanup(save_patch.stop)

        auth_patch = patch("auth.requests.get", return_value=Mock(status_code=200, json=lambda: IDENTIDAD_OK))
        auth_patch.start()
        self.addCleanup(auth_patch.stop)

    def test_api_conecta_perfil_elegido_con_trabajo(self):
        with patch("main.create_job", return_value={
            "scan_id": "scan-web", "target": "192.0.2.10", "profile": "web",
            "status": "running", "events": [],
        }) as create:
            response = self.client.post("/scan", json={"target": " 192.0.2.10 ", "profile": "web"},
                                        headers=CABECERA)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["profile"], "web")
        create.assert_called_once_with("192.0.2.10", "web")

    def test_falla_si_nmap_no_crea_xml_y_se_limpia_temporal(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
        job = nuevo_job("scan-fail")
        with patch("jobs.start_nmap", return_value=FakeProcess()), \
             patch("jobs.publish_events_to_siem"):
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "failed")
        self.assertIn("informe XML", job["error"])
        self.assertEqual(public(job)["error"], job["error"])
        self.assertFalse(os.path.exists(path))

    def test_nmap_no_cero_falla_sin_publicar(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
            file.write(b"no debe procesarse")
        job = nuevo_job("scan-exit")
        with patch("jobs.start_nmap", return_value=FakeProcess(returncode=2)), \
             patch("jobs.publish_events_to_siem") as publish:
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "failed")
        self.assertIn("código 2", job["error"])
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

        job = nuevo_job("scan-ok")
        with patch("jobs.start_nmap", side_effect=start_nmap), \
             patch("jobs.publish_events_to_siem") as publish:
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "completed")
        finding = next(event for event in job["events"]
                       if event["event_type"] == "vulnerability_detected")
        self.assertEqual(finding["source"], "scanner")
        self.assertEqual(finding["details"]["profile"], "vuln")
        self.assertEqual(finding["details"]["scan_id"], "scan-ok")
        # Los hallazgos deben enviarse al SIEM (G5)
        publish.assert_called_once_with(job["events"], scan_id="scan-ok")
        self.assertFalse(os.path.exists(path))

    def test_timeout_termina_proceso_y_marca_fallo(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
        process = TimeoutProcess()
        job = nuevo_job("scan-timeout")
        with patch("jobs.start_nmap", return_value=process), \
             patch("jobs.publish_events_to_siem"):
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "failed")
        self.assertIn("superó el límite", job["error"])
        self.assertEqual(process.returncode, -9)
        self.assertFalse(os.path.exists(path))


class TestSiemDelivery(unittest.TestCase):
    """publish_events_to_siem devuelve solo un resumen; el detalle de errores va al log."""

    def resumen(self, status, total, delivered, failed):
        return {"status": status, "total": total, "delivered": delivered, "failed": failed}

    def test_acepta_acuse_correcto(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "success", "event_id": "evt-001"}

        with patch("jobs.requests.post", return_value=response) as post:
            result = publish_events_to_siem([{"event_id": "evt-001", "source": "scanner"}])

        post.assert_called_once()
        self.assertEqual(result, self.resumen("delivered", 1, 1, 0))

    def test_registra_error_http_del_siem(self):
        with patch("jobs.requests.post", return_value=Mock(status_code=400)):
            result = publish_events_to_siem([{"event_id": "evt-002", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_ack_no_json(self):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("respuesta no válida")

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([{"event_id": "evt-003", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_status_incorrecto_del_siem(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "error", "event_id": "evt-004"}

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([{"event_id": "evt-004", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_event_id_distinto(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "success", "event_id": "evt-otro"}

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([{"event_id": "evt-005", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_timeout_de_conexion(self):
        with patch("jobs.requests.post", side_effect=requests.exceptions.Timeout):
            result = publish_events_to_siem([{"event_id": "evt-006", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_aborta_tras_tres_fallos_de_conexion_seguidos(self):
        eventos = [{"event_id": f"evt-{i}", "source": "scanner"} for i in range(5)]

        with patch("jobs.requests.post", side_effect=requests.exceptions.ConnectionError) as post:
            result = publish_events_to_siem(eventos)

        self.assertEqual(post.call_count, 3)  # no insiste con los otros 2
        self.assertEqual(result, self.resumen("failed", 5, 0, 5))

    def test_registra_entrega_parcial(self):
        ok_response = Mock(status_code=200)
        ok_response.json.return_value = {"status": "success", "event_id": "evt-007"}

        with patch("jobs.requests.post", side_effect=[ok_response, Mock(status_code=400)]):
            result = publish_events_to_siem([
                {"event_id": "evt-007", "source": "scanner"},
                {"event_id": "evt-008", "source": "scanner"},
            ])

        self.assertEqual(result, self.resumen("partial", 2, 1, 1))

    def test_registra_ack_que_no_es_objeto(self):
        response = Mock(status_code=200)
        response.json.return_value = []

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem([{"event_id": "evt-009", "source": "scanner"}])

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_sin_eventos_no_contacta_al_siem(self):
        with patch("jobs.requests.post") as post:
            result = publish_events_to_siem([])

        self.assertEqual(result, self.resumen("not_required", 0, 0, 0))
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)

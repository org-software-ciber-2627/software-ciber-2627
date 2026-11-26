import os
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

import history
import jobs
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
    return {
        "scan_id": scan_id,
        "target": "192.0.2.10",
        "profile": "vuln",
        "status": "running",
        "events": [],
    }


class TestScannerFlow(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

        # El worker guarda en el historial: lo simulamos para no tocar ninguna BBDD
        save_patch = patch("jobs.save_job")
        save_patch.start()
        self.addCleanup(save_patch.stop)

        auth_patch = patch(
            "auth.requests.get",
            return_value=Mock(status_code=200, json=lambda: IDENTIDAD_OK),
        )
        auth_patch.start()
        self.addCleanup(auth_patch.stop)

    def test_api_conecta_perfil_elegido_con_trabajo(self):
        with patch(
            "main.create_job",
            return_value={
                "scan_id": "scan-web",
                "target": "192.0.2.10",
                "profile": "web",
                "status": "running",
                "events": [],
            },
        ) as create:
            response = self.client.post(
                "/scan",
                json={"target": " 192.0.2.10 ", "profile": "web"},
                headers=CABECERA,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["profile"], "web")
        create.assert_called_once_with("192.0.2.10", "web")

    def test_falla_si_nmap_no_crea_xml_y_se_limpia_temporal(self):
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name
        job = nuevo_job("scan-fail")
        with patch("jobs.start_nmap", return_value=FakeProcess()), patch(
            "jobs.publish_events_to_siem"
        ):
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
        with patch("jobs.start_nmap", return_value=FakeProcess(returncode=2)), patch(
            "jobs.publish_events_to_siem"
        ) as publish:
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "failed")
        self.assertIn("código 2", job["error"])
        publish.assert_not_called()
        self.assertFalse(os.path.exists(path))

    def test_informe_valido_se_normaliza_y_publica_al_siem(self):
        xml = """<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4" />
        <ports><port protocol="tcp" portid="443"><state state="open" />
        <service name="https" /><script id="demo" output="VULNERABLE: ejemplo" />
        </port></ports></host></nmaprun>"""
        with tempfile.NamedTemporaryFile(delete=False) as file:
            path = file.name

        def start_nmap(target, profile, outfile):
            with open(outfile, "w", encoding="utf-8") as output:
                output.write(xml)
            return FakeProcess()

        job = nuevo_job("scan-ok")
        with patch("jobs.start_nmap", side_effect=start_nmap), patch(
            "jobs.publish_events_to_siem"
        ) as publish:
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "completed")
        finding = next(
            event
            for event in job["events"]
            if event["event_type"] == "vulnerability_detected"
        )
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
        with patch("jobs.start_nmap", return_value=process), patch(
            "jobs.publish_events_to_siem"
        ):
            _run_job_worker(job, path)

        self.assertEqual(job["status"], "failed")
        self.assertIn("superó el límite", job["error"])
        self.assertEqual(process.returncode, -9)
        self.assertFalse(os.path.exists(path))


class TestSiemDelivery(unittest.TestCase):
    """publish_events_to_siem devuelve solo un resumen; el detalle de errores va al log."""

    def setUp(self):
        self._reset_token_state()
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)

        db_patch = patch.object(
            history, "DB_PATH", os.path.join(self._tmpdir.name, "test_scans.db")
        )
        db_patch.start()
        self.addCleanup(db_patch.stop)
        history.init_db()

        token_patch = patch("jobs.get_token", return_value="jwt-prueba")
        token_patch.start()
        self.addCleanup(token_patch.stop)

    def resumen(self, status, total, delivered, failed):
        return {
            "status": status,
            "total": total,
            "delivered": delivered,
            "failed": failed,
        }

    def _reset_token_state(self):
        jobs._TOKEN = None
        jobs._TOKEN_OBTAINED_AT = 0.0
        jobs._RATE_LIMITED_UNTIL = 0.0

    def _real_get_token_side_effect(self):
        """Ejecuta el flujo real de get_token contra jobs.requests.post."""
        import time as _time

        def _impl(force=False):
            now = _time.monotonic()
            if now < jobs._RATE_LIMITED_UNTIL:
                raise jobs.RateLimitError(round(jobs._RATE_LIMITED_UNTIL - now, 2))
            if (
                not force
                and jobs._TOKEN
                and (now - jobs._TOKEN_OBTAINED_AT) < jobs.TOKEN_REFRESH_SECONDS
            ):
                return jobs._TOKEN

            resp = jobs.requests.post(
                jobs._login_url(),
                json={"username": "svc-escaner", "password": ""},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=3,
            )
            if resp.status_code == 429:
                retry_after = jobs._parse_retry_after(resp)
                jobs._RATE_LIMITED_UNTIL = _time.monotonic() + retry_after
                raise jobs.RateLimitError(retry_after)
            resp.raise_for_status()
            token = resp.json().get("token")
            jobs._TOKEN = token
            jobs._TOKEN_OBTAINED_AT = now
            return token

        return _impl

    def test_acepta_acuse_correcto(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "success", "event_id": "evt-001"}

        with patch("jobs.requests.post", return_value=response) as post:
            result = publish_events_to_siem(
                [{"event_id": "evt-001", "source": "scanner"}]
            )

        post.assert_called_once()
        self.assertEqual(result, self.resumen("delivered", 1, 1, 0))

    def test_registra_error_http_del_siem(self):
        with patch("jobs.requests.post", return_value=Mock(status_code=400)):
            result = publish_events_to_siem(
                [{"event_id": "evt-002", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_ack_no_json(self):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("respuesta no válida")

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem(
                [{"event_id": "evt-003", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_status_incorrecto_del_siem(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "error", "event_id": "evt-004"}

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem(
                [{"event_id": "evt-004", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_event_id_distinto(self):
        response = Mock(status_code=200)
        response.json.return_value = {"status": "success", "event_id": "evt-otro"}

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem(
                [{"event_id": "evt-005", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_registra_timeout_de_conexion(self):
        with patch("jobs.requests.post", side_effect=requests.exceptions.Timeout), patch(
            "jobs.time.sleep"
        ):
            result = publish_events_to_siem(
                [{"event_id": "evt-006", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_aborta_tras_tres_fallos_de_conexion_seguidos(self):
        eventos = [{"event_id": f"evt-{i}", "source": "scanner"} for i in range(5)]

        with patch(
            "jobs.requests.post", side_effect=requests.exceptions.ConnectionError
        ) as post, patch("jobs.time.sleep"):
            result = publish_events_to_siem(eventos)

        expected_calls = 3 * (jobs.MAX_TRANSIENT_RETRIES + 1)
        self.assertEqual(post.call_count, expected_calls)
        self.assertEqual(result, self.resumen("failed", 5, 0, 5))

    def test_registra_entrega_parcial(self):
        ok_response = Mock(status_code=200)
        ok_response.json.return_value = {"status": "success", "event_id": "evt-007"}

        with patch(
            "jobs.requests.post", side_effect=[ok_response, Mock(status_code=400)]
        ):
            result = publish_events_to_siem(
                [
                    {"event_id": "evt-007", "source": "scanner"},
                    {"event_id": "evt-008", "source": "scanner"},
                ]
            )

        self.assertEqual(result, self.resumen("partial", 2, 1, 1))

    def test_registra_ack_que_no_es_objeto(self):
        response = Mock(status_code=200)
        response.json.return_value = []

        with patch("jobs.requests.post", return_value=response):
            result = publish_events_to_siem(
                [{"event_id": "evt-009", "source": "scanner"}]
            )

        self.assertEqual(result, self.resumen("failed", 1, 0, 1))

    def test_sin_eventos_no_contacta_al_siem(self):
        with patch("jobs.requests.post") as post:
            result = publish_events_to_siem([])

        self.assertEqual(result, self.resumen("not_required", 0, 0, 0))
        post.assert_not_called()

    def test_envia_bearer_y_reutiliza_token_en_cache(self):
        self._reset_token_state()

        login_resp = Mock(status_code=200)
        login_resp.json.return_value = {"token": "jwt-servicio-1"}

        ok_1 = Mock(status_code=200)
        ok_1.json.return_value = {"status": "success", "event_id": "evt-1"}
        ok_2 = Mock(status_code=200)
        ok_2.json.return_value = {"status": "success", "event_id": "evt-2"}

        calls = []

        def fake_post(url, json=None, headers=None, timeout=3):
            calls.append((url, json, headers))
            if url.endswith("/auth/login"):
                return login_resp
            return ok_1 if json["event_id"] == "evt-1" else ok_2

        with patch("jobs.get_token", side_effect=self._real_get_token_side_effect()), patch(
            "jobs.requests.post", side_effect=fake_post
        ):
            result = publish_events_to_siem(
                [
                    {
                        "event_id": "evt-1",
                        "timestamp": "2026-11-26T10:00:00Z",
                        "source": "scanner",
                    },
                    {
                        "event_id": "evt-2",
                        "timestamp": "2026-11-26T10:00:01Z",
                        "source": "scanner",
                    },
                ]
            )

        self.assertEqual(result, self.resumen("delivered", 2, 2, 0))
        login_calls = [c for c in calls if c[0].endswith("/auth/login")]
        event_calls = [c for c in calls if not c[0].endswith("/auth/login")]
        self.assertEqual(len(login_calls), 1)
        self.assertEqual(len(event_calls), 2)
        self.assertEqual(event_calls[0][2]["Authorization"], "Bearer jwt-servicio-1")
        self.assertEqual(event_calls[1][2]["Authorization"], "Bearer jwt-servicio-1")

    def test_401_renueva_token_y_reintenta_una_vez_conservando_evento(self):
        self._reset_token_state()

        login_count = 0
        event_payloads = []

        def fake_post(url, json=None, headers=None, timeout=3):
            nonlocal login_count
            if url.endswith("/auth/login"):
                login_count += 1
                resp = Mock(status_code=200)
                resp.json.return_value = {"token": f"jwt-{login_count}"}
                return resp

            event_payloads.append((dict(json), dict(headers or {})))
            if len(event_payloads) == 1:
                return Mock(status_code=401)
            resp = Mock(status_code=200)
            resp.json.return_value = {"status": "success", "event_id": json["event_id"]}
            return resp

        evento = {
            "event_id": "evt-401",
            "timestamp": "2026-11-26T10:05:00Z",
            "source": "scanner",
        }

        with patch("jobs.get_token", side_effect=self._real_get_token_side_effect()), patch(
            "jobs.requests.post", side_effect=fake_post
        ):
            result = publish_events_to_siem([evento])

        self.assertEqual(result, self.resumen("delivered", 1, 1, 0))
        self.assertEqual(login_count, 2)
        self.assertEqual(len(event_payloads), 2)
        self.assertEqual(event_payloads[0][1]["Authorization"], "Bearer jwt-1")
        self.assertEqual(event_payloads[1][1]["Authorization"], "Bearer jwt-2")
        self.assertEqual(event_payloads[0][0], evento)
        self.assertEqual(event_payloads[1][0], evento)

    def test_429_en_login_respeta_retry_after_sin_bucle(self):
        self._reset_token_state()

        resp_429 = Mock(status_code=429, headers={"Retry-After": "30"})
        login_calls = []

        def fake_post(url, json=None, headers=None, timeout=3):
            if url.endswith("/auth/login"):
                login_calls.append(url)
                return resp_429
            resp = Mock(status_code=200)
            resp.json.return_value = {
                "status": "success",
                "event_id": (json or {}).get("event_id"),
            }
            return resp

        with patch("jobs.get_token", side_effect=self._real_get_token_side_effect()), patch(
            "jobs.requests.post", side_effect=fake_post
        ):
            result = publish_events_to_siem(
                [
                    {
                        "event_id": "evt-429-1",
                        "timestamp": "2026-11-26T10:10:00Z",
                        "source": "scanner",
                    },
                    {
                        "event_id": "evt-429-2",
                        "timestamp": "2026-11-26T10:10:01Z",
                        "source": "scanner",
                    },
                ]
            )

        self.assertEqual(len(login_calls), 1)
        self.assertEqual(result, self.resumen("failed", 2, 0, 2))

    def test_503_reintenta_con_espera_conservando_evento(self):
        envios = []
        sleeps = []

        def fake_post(url, json=None, headers=None, timeout=3):
            envios.append(dict(json))
            if len(envios) == 1:
                return Mock(status_code=503)
            resp = Mock(status_code=200)
            resp.json.return_value = {"status": "success", "event_id": json["event_id"]}
            return resp

        evento = {
            "event_id": "evt-503",
            "timestamp": "2026-11-26T10:15:00Z",
            "source": "scanner",
        }

        with patch("jobs.requests.post", side_effect=fake_post), patch(
            "jobs.time.sleep", side_effect=lambda s: sleeps.append(s)
        ):
            result = publish_events_to_siem([evento])

        self.assertEqual(result, self.resumen("delivered", 1, 1, 0))
        self.assertEqual(len(envios), 2)
        self.assertEqual(envios[0], evento)
        self.assertEqual(envios[1], evento)
        self.assertEqual(len(sleeps), 1)

    def test_409_es_rechazo_definitivo_sin_reintentar(self):
        envios = []

        def fake_post(url, json=None, headers=None, timeout=3):
            envios.append(dict(json))
            return Mock(status_code=409)

        with patch("jobs.requests.post", side_effect=fake_post):
            result = publish_events_to_siem(
                [
                    {
                        "event_id": "evt-409",
                        "timestamp": "2026-11-26T10:20:00Z",
                        "source": "scanner",
                    }
                ]
            )

        self.assertEqual(len(envios), 1)
        self.assertEqual(result, self.resumen("failed", 1, 0, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
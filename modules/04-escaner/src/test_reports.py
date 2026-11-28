import os
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import Mock, patch

import history
from history import init_db, load_job, save_job
from main import app

# Identidad (G1) simulada: el token se da por válido con rol analista
IDENTIDAD_OK = {"valid": True, "user_id": 1, "username": "test", "role": "analista"}
CABECERA = {"Authorization": "Bearer token-de-prueba"}


class TestReports(unittest.TestCase):
    def setUp(self):
        self.config_patch = patch.dict(app.config, {"TESTING": True})
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

        self.client = app.test_client()

        # Base de datos temporal y vacía para cada test
        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        db_patch = patch.object(history, "DB_PATH", os.path.join(carpeta.name, "scans.db"))
        db_patch.start()
        self.addCleanup(db_patch.stop)
        init_db()

        auth_patch = patch("auth.requests.get", return_value=Mock(status_code=200, json=lambda: IDENTIDAD_OK))
        auth_patch.start()
        self.addCleanup(auth_patch.stop)

    def consultar(self, scan_id):
        return self.client.get(f"/scans/{scan_id}/report", headers=CABECERA)

    def crear(self, scan_id, estado, eventos=None, error=None):
        save_job({
            "scan_id": scan_id, "created_at": "2026-11-03T10:00:00Z", "target": "192.0.2.10",
            "profile": "vuln", "status": estado, "events": eventos or [], "error": error,
        })

    def test_inexistente(self):
        respuesta = self.consultar("no-existe")

        self.assertEqual(respuesta.status_code, 404)
        self.assertEqual(respuesta.get_json()["error"]["codigo"], "SCAN_NOT_FOUND")

    def test_pendiente_y_en_curso(self):
        for estado, esperado in (("pending", "pendiente"), ("running", "en_curso")):
            with self.subTest(estado=estado):
                self.crear("prueba", estado)

                respuesta = self.consultar("prueba")
                datos = respuesta.get_json()

                self.assertEqual(respuesta.status_code, 202)
                self.assertEqual(datos["scan_id"], "prueba")
                self.assertEqual(datos["estado"], esperado)
                self.assertIn("mensaje", datos)

    def test_terminado_sin_eventos(self):
        self.crear("vacio", "completed")

        respuesta = self.consultar("vacio")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json(), [])

    def test_escaneo_fallido(self):
        self.crear("fallido", "failed", error="Detalle técnico privado")

        respuesta = self.consultar("fallido")

        self.assertEqual(respuesta.status_code, 500)
        self.assertEqual(respuesta.get_json()["error"]["codigo"], "SCAN_FAILED")
        self.assertNotIn("Detalle técnico privado", respuesta.get_data(as_text=True))

    def test_informe_invalido(self):
        # Datos corruptos que no se pueden guardar en la BBDD: se simula get_job directamente
        casos = [
            {"status": "completed"},
            {"status": "completed", "events": None},
            {"status": "completed", "events": {}},
            {"status": "desconocido", "events": []},
            {"status": "completed", "events": [None]},
        ]
        for job in casos:
            with self.subTest(job=job):
                with patch("reports.get_job", return_value=job):
                    respuesta = self.consultar("invalido")

                self.assertEqual(respuesta.status_code, 500)
                self.assertEqual(respuesta.get_json()["error"]["codigo"], "INTERNAL_ERROR")

    def test_error_inesperado(self):
        with patch("reports.get_job", side_effect=RuntimeError("Fallo simulado")):
            respuesta = self.consultar("prueba")

        self.assertEqual(respuesta.status_code, 500)
        self.assertEqual(respuesta.get_json()["error"]["codigo"], "INTERNAL_ERROR")
        self.assertNotIn("Fallo simulado", respuesta.get_data(as_text=True))

    def test_eventos_informativos_no_son_vulnerabilidades(self):
        self.crear("informativo", "completed", [
            {"event_type": "port_open"},
            {"event_type": "service_detected"},
        ])

        respuesta = self.consultar("informativo")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json(), [])

    def test_filtra_y_adapta_sin_modificar_originales(self):
        vulnerabilidad = {
            "event_id": "evento-1",
            "timestamp": "2026-11-03T10:00:00Z",
            "source": "scanner",
            "event_type": "cve_detected",
            "severity": "high",
            "title": "Vulnerabilidad de prueba",
            "description": "Hallazgo simulado para el test.",
            "details": {
                "target": {"ip": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"},
                "scan_id": "vulnerabilidades",
                "tool": "nmap",
                "profile": "vuln",
                "script_id": "script-de-prueba",
                "evidence": "Evidencia simulada",
                "cve": "CVE-2014-0160",
                "cvss": 7.5,
            },
        }

        sin_cve = deepcopy(vulnerabilidad)
        sin_cve["event_id"] = "evento-2"
        sin_cve["event_type"] = "vulnerability_detected"
        sin_cve["details"]["cve"] = None
        sin_cve["details"]["cvss"] = None

        eventos = [{"event_type": "port_open"}, vulnerabilidad, {"event_type": "service_detected"}, sin_cve]
        originales = deepcopy(eventos)
        self.crear("vulnerabilidades", "completed", eventos)

        esperado = [deepcopy(vulnerabilidad), deepcopy(sin_cve)]
        esperado[0]["event_type"] = "vulnerability_detected"

        # Consultar varias veces no debe cambiar los IDs ni los eventos guardados.
        for _ in range(2):
            respuesta = self.consultar("vulnerabilidades")

            self.assertEqual(respuesta.status_code, 200)
            self.assertTrue(respuesta.is_json)
            self.assertEqual(respuesta.get_json(), esperado)
            self.assertEqual(load_job("vulnerabilidades")["events"], originales)

    def test_sin_token_responde_401(self):
        respuesta = self.client.get("/scans/prueba/report")

        self.assertEqual(respuesta.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)

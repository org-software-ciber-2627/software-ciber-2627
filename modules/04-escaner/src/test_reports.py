import unittest
from copy import deepcopy
from unittest.mock import patch

from main import app
from jobs import JOBS


class TestReports(unittest.TestCase):
    def setUp(self):
        self.config_patch = patch.dict(app.config, {"TESTING": True})
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

        self.client = app.test_client()

        # Aislamos los trabajos de prueba y restauramos el contenido al acabar.
        self.jobs_patch = patch.dict(JOBS, {}, clear=True)
        self.jobs_patch.start()
        self.addCleanup(self.jobs_patch.stop)

    def consultar(self, scan_id):
        return self.client.get(f"/scans/{scan_id}/report")

    def test_inexistente(self):
        respuesta = self.consultar("no-existe")

        self.assertEqual(respuesta.status_code, 404)
        self.assertEqual(
            respuesta.get_json()["error"]["codigo"],
            "SCAN_NOT_FOUND",
        )

    def test_pendiente_y_en_curso(self):
        for estado, esperado in (
            ("pending", "pendiente"),
            ("running", "en_curso"),
        ):
            with self.subTest(estado=estado):
                JOBS["prueba"] = {
                    "status": estado,
                    "events": [],
                }

                respuesta = self.consultar("prueba")
                datos = respuesta.get_json()

                self.assertEqual(respuesta.status_code, 202)
                self.assertEqual(datos["scan_id"], "prueba")
                self.assertEqual(datos["estado"], esperado)
                self.assertIn("mensaje", datos)

    def test_terminado_sin_eventos(self):
        JOBS["vacio"] = {
            "status": "completed",
            "events": [],
        }

        respuesta = self.consultar("vacio")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json(), [])

    def test_escaneo_fallido(self):
        JOBS["fallido"] = {
            "status": "failed",
            "error": "Detalle técnico privado",
            "events": [],
        }

        respuesta = self.consultar("fallido")

        self.assertEqual(respuesta.status_code, 500)
        self.assertEqual(
            respuesta.get_json()["error"]["codigo"],
            "SCAN_FAILED",
        )
        self.assertNotIn(
            "Detalle técnico privado",
            respuesta.get_data(as_text=True),
        )

    def test_informe_invalido(self):
        casos = [
            {"status": "completed"},
            {"status": "completed", "events": None},
            {"status": "completed", "events": {}},
            {"status": "desconocido", "events": []},
            {"status": "completed", "events": [None]},
        ]

        for job in casos:
            with self.subTest(job=job):
                JOBS["invalido"] = job
                respuesta = self.consultar("invalido")

                self.assertEqual(respuesta.status_code, 500)
                self.assertEqual(
                    respuesta.get_json()["error"]["codigo"],
                    "INTERNAL_ERROR",
                )

    def test_error_inesperado(self):
        with patch(
            "reports.get_job",
            side_effect=RuntimeError("Fallo simulado"),
        ):
            respuesta = self.consultar("prueba")

        self.assertEqual(respuesta.status_code, 500)
        self.assertEqual(
            respuesta.get_json()["error"]["codigo"],
            "INTERNAL_ERROR",
        )
        self.assertNotIn(
            "Fallo simulado",
            respuesta.get_data(as_text=True),
        )

    def test_eventos_informativos_no_son_vulnerabilidades(self):
        JOBS["informativo"] = {
            "status": "completed",
            "events": [
                {"event_type": "port_open"},
                {"event_type": "service_detected"},
            ],
        }

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
                "target": {
                    "ip": "192.0.2.10",
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                },
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

        eventos = [
            {"event_type": "port_open"},
            vulnerabilidad,
            {"event_type": "service_detected"},
            sin_cve,
        ]

        originales = deepcopy(eventos)
        JOBS["vulnerabilidades"] = {
            "status": "completed",
            "events": eventos,
        }

        esperado = [
            deepcopy(vulnerabilidad),
            deepcopy(sin_cve),
        ]
        esperado[0]["event_type"] = "vulnerability_detected"

        # Consultar varias veces no debe cambiar los IDs ni los eventos.
        for _ in range(2):
            respuesta = self.consultar("vulnerabilidades")

            self.assertEqual(respuesta.status_code, 200)
            self.assertTrue(respuesta.is_json)
            self.assertEqual(respuesta.get_json(), esperado)
            self.assertEqual(
                JOBS["vulnerabilidades"]["events"],
                originales,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
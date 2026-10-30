import unittest
from unittest.mock import patch

from main import app
from jobs import JOBS


class TestReports(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

        # Datos temporales solo para estas pruebas.
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
                JOBS["prueba"] = {"status": estado, "events": []}
                respuesta = self.consultar("prueba")

                self.assertEqual(respuesta.status_code, 202)
                self.assertEqual(
                    respuesta.get_json()["estado"], esperado
                )

    def test_terminado_sin_eventos(self):
        JOBS["vacio"] = {"status": "completed", "events": []}
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
        JOBS["invalido"] = {
            "status": "completed",
            "events": None,
        }
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
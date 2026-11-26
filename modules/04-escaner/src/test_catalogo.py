import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import history
from history import init_db, load_job, save_job
from main import app

# Identidad (G1) simulada: el token se da por válido con rol analista
IDENTIDAD_OK = {"valid": True, "user_id": 1, "username": "test", "role": "analista"}
CABECERA = {"Authorization": "Bearer token-de-prueba"}


class TestCatalogo(unittest.TestCase):
    def setUp(self):
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

    def get(self, ruta):
        return self.client.get(ruta, headers=CABECERA)

    def job(self, identificador, fecha=None, estado="completed", eventos=None):
        save_job({
            "scan_id": identificador, "created_at": fecha, "target": "192.0.2.10",
            "profile": "vuln", "status": estado, "events": eventos or [],
        })

    def test_health(self):
        r = self.client.get("/health")  # /health no pide token
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok", "module": "04-escaner"})

    def test_catalogo_vacio(self):
        for ruta in ("/scans", "/events"):
            with self.subTest(ruta=ruta):
                r = self.get(ruta)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.get_json(), [])

    def test_catalogo_ordenado_y_alias_sin_modificar_trabajos(self):
        self.job("sin-fecha")
        self.job("anterior", "2026-11-04T10:00:00Z", eventos=[{"event_id": "a"}])
        self.job("reciente", "2026-11-05T10:00:00Z")
        originales = {i: load_job(i) for i in ("sin-fecha", "anterior", "reciente")}
        r = self.get("/scans")
        self.assertEqual(r.status_code, 200)
        datos = r.get_json()
        self.assertEqual([j["scan_id"] for j in datos], ["reciente", "anterior", "sin-fecha"])
        self.assertEqual(datos[0]["created_at"], "2026-11-05T10:00:00Z")
        self.assertIsNone(datos[-1]["created_at"])           # contrato: null si no hay fecha
        self.assertTrue(all("events" not in j for j in datos))  # contrato: sin eventos
        self.assertEqual(self.get("/events").get_json(), datos)
        self.assertEqual({i: load_job(i) for i in originales}, originales)

    def test_diff_parametros_y_escaneos_inexistentes(self):
        for ruta in ("/diff", "/diff?base=a", "/diff?target=b"):
            self.assertEqual(self.get(ruta).status_code, 400)
        self.assertEqual(self.get("/diff?base=a&target=b").status_code, 404)

    def test_diff_rechaza_estados_no_completados(self):
        for lado in ("a", "b"):
            for estado, codigo in (("pending", 409), ("running", 409), ("failed", 409), ("desconocido", 500)):
                with self.subTest(lado=lado, estado=estado):
                    self.job("a")
                    self.job("b")
                    self.job(lado, estado=estado)
                    r = self.get("/diff?base=a&target=b")
                    self.assertEqual(r.status_code, codigo)
                    self.assertIsInstance(r.get_json()["error"], str)

    def test_diff_distingue_ip_y_puerto_en_details(self):
        def evento(ip, puerto):
            return {"title": "Mismo hallazgo", "details": {"target": {"ip": ip, "port": puerto}}}
        comun = evento("192.0.2.10", 80)
        ausente = evento("192.0.2.10", 443)
        nuevo = evento("192.0.2.11", 80)
        self.job("a", eventos=[comun, ausente])
        self.job("b", eventos=[comun, nuevo])
        r = self.get("/diff?base=a&target=b")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {
            "base_scan_id": "a", "target_scan_id": "b",
            "diff": {"new": [nuevo], "fixed": [ausente], "unchanged": [comun]},
        })

    def test_diff_completados_vacios(self):
        self.job("a")
        self.job("b")
        r = self.get("/diff?base=a&target=b")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["diff"], {"new": [], "fixed": [], "unchanged": []})

    def test_diff_conserva_eventos_con_firmas_duplicadas(self):
        def evento(event_id, evidencia):
            return {
                "event_id": event_id,
                "title": "Mismo hallazgo",
                "details": {
                    "target": {"ip": "192.0.2.10", "port": 443},
                    "evidence": evidencia,
                },
            }

        base_uno = evento("base-1", "evidencia 1")
        base_dos = evento("base-2", "evidencia 2")
        target_uno = evento("target-1", "evidencia distinta")
        target_dos = evento("target-2", "otra evidencia")
        target_tres = evento("target-3", "tercera evidencia")
        self.job("a", eventos=[base_uno, base_dos])
        self.job("b", eventos=[target_uno, target_dos, target_tres])

        r = self.get("/diff?base=a&target=b")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["diff"], {
            "new": [target_tres],
            "fixed": [],
            "unchanged": [base_uno, base_dos],
        })

    def test_diff_datos_de_eventos_invalidos_responden_500(self):
        self.job("a", eventos=[{"title": "sin details.target"}])
        self.job("b")

        r = self.get("/diff?base=a&target=b")

        self.assertEqual(r.status_code, 500)
        self.assertIsInstance(r.get_json()["error"], str)

    def test_sin_token_responde_401(self):
        self.assertEqual(self.client.get("/scans").status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)

import unittest
from copy import deepcopy
from unittest.mock import patch

from main import app
from jobs import JOBS


class TestCatalogo(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.jobs_patch = patch.dict(JOBS, {}, clear=True)
        self.jobs_patch.start()
        self.addCleanup(self.jobs_patch.stop)

    def job(self, identificador, fecha=None, estado="completed", eventos=None):
        JOBS[identificador] = {
            "scan_id": identificador, "target": "192.0.2.10",
            "profile": "vuln", "status": estado,
            "events": eventos or [],
        }
        if fecha is not None:
            JOBS[identificador]["created_at"] = fecha

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok", "module": "04-escaner"})

    def test_catalogo_vacio(self):
        for ruta in ("/scans", "/events"):
            with self.subTest(ruta=ruta):
                r = self.client.get(ruta)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.get_json(), [])

    def test_catalogo_ordenado_y_alias_sin_modificar_trabajos(self):
        self.job("sin-fecha")
        self.job("anterior", "2026-11-04T10:00:00Z", eventos=[{"event_id": "a"}])
        self.job("reciente", "2026-11-05T10:00:00Z")
        originales = deepcopy(JOBS)
        r = self.client.get("/scans")
        self.assertEqual(r.status_code, 200)
        datos = r.get_json()
        self.assertEqual([j["scan_id"] for j in datos], ["reciente", "anterior", "sin-fecha"])
        self.assertEqual(datos[0]["created_at"], "2026-11-05T10:00:00Z")
        self.assertIsNone(datos[-1]["created_at"])
        self.assertTrue(all("events" not in j for j in datos))
        self.assertEqual(self.client.get("/events").get_json(), datos)
        self.assertEqual(JOBS, originales)

    def test_diff_parametros_y_escaneos_inexistentes(self):
        for ruta in ("/diff", "/diff?base=a", "/diff?target=b"):
            self.assertEqual(self.client.get(ruta).status_code, 400)
        self.assertEqual(self.client.get("/diff?base=a&target=b").status_code, 404)

    def test_diff_rechaza_estados_no_completados(self):
        for lado in ("a", "b"):
            for estado, codigo in (("pending", 409), ("running", 409), ("failed", 409), ("desconocido", 500)):
                with self.subTest(lado=lado, estado=estado):
                    self.job("a")
                    self.job("b")
                    JOBS[lado]["status"] = estado
                    r = self.client.get("/diff?base=a&target=b")
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
        originales = deepcopy(JOBS)
        r = self.client.get("/diff?base=a&target=b")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {
            "base_scan_id": "a", "target_scan_id": "b",
            "diff": {"new": [nuevo], "fixed": [ausente], "unchanged": [comun]},
        })
        self.assertEqual(JOBS, originales)

    def test_diff_completados_vacios(self):
        self.job("a")
        self.job("b")
        r = self.client.get("/diff?base=a&target=b")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["diff"], {"new": [], "fixed": [], "unchanged": []})


if __name__ == "__main__":
    unittest.main(verbosity=2)

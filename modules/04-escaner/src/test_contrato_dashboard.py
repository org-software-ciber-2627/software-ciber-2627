import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

import history
from history import init_db, save_job
from main import app

# Carpeta con los JSON de ejemplo que acordamos con el Dashboard (G7)
CONTRATO = Path(__file__).resolve().parents[1] / "contract" / "dashboard"

# Respuesta simulada de Identidad (G1) para un analista con sesión válida
IDENTIDAD_OK = {"valid": True, "user_id": 1, "username": "analista.test", "role": "analista"}
CABECERA = {"Authorization": "Bearer token-de-prueba"}


def ejemplo(nombre):
    """Lee uno de los JSON de ejemplo del contrato."""
    return json.loads((CONTRATO / nombre).read_text(encoding="utf-8"))


class TestContratoDashboard(unittest.TestCase):
    """Comprueba que la API real responde igual que los ejemplos del contrato con el G7."""

    def setUp(self):
        self.client = app.test_client()

        # Base de datos temporal y vacía para cada test (no toca data/scans.db)
        carpeta = tempfile.TemporaryDirectory()
        self.addCleanup(carpeta.cleanup)
        db_patch = patch.object(history, "DB_PATH", os.path.join(carpeta.name, "scans.db"))
        db_patch.start()
        self.addCleanup(db_patch.stop)
        init_db()

        # Simulamos que Identidad valida el token como analista
        auth_patch = patch("auth.requests.get", return_value=Mock(status_code=200, json=lambda: IDENTIDAD_OK))
        auth_patch.start()
        self.addCleanup(auth_patch.stop)

    def get(self, ruta):
        return self.client.get(ruta, headers=CABECERA)

    def crear_escaneo(self, scan_id, estado, eventos=None, created_at="2026-11-06T10:30:00Z"):
        save_job({
            "scan_id": scan_id,
            "created_at": created_at,
            "target": "192.0.2.10",
            "profile": "vuln",
            "status": estado,
            "events": eventos or [],
        })

    def test_catalogo(self):
        for escaneo in ejemplo("catalogo.json"):
            save_job({**escaneo, "events": []})

        respuesta = self.get("/scans")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json(), ejemplo("catalogo.json"))

    def test_informe_con_hallazgos(self):
        esperado = ejemplo("informe_con_hallazgos.json")
        eventos = deepcopy(esperado)
        eventos[1]["event_type"] = "cve_detected"    # así se guarda internamente
        eventos.append({"event_type": "port_open"})  # informativo: no debe salir
        self.crear_escaneo("scan-001", "completed", eventos)

        respuesta = self.get("/scans/scan-001/report")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json(), esperado)

    def test_estados_y_errores(self):
        casos = [
            # scan_id,    estado,        código HTTP, ejemplo esperado
            ("scan-002", "completed",   200, "informe_vacio.json"),
            ("scan-003", "pending",     202, "pendiente.json"),
            ("scan-003", "running",     202, "en_curso.json"),
            ("scan-001", "failed",      500, "error_500_escaneo.json"),
            ("scan-001", "desconocido", 500, "error_500_interno.json"),
        ]
        for scan_id, estado, codigo, archivo in casos:
            with self.subTest(estado=estado):
                self.crear_escaneo(scan_id, estado)

                respuesta = self.get(f"/scans/{scan_id}/report")

                self.assertEqual(respuesta.status_code, codigo)
                self.assertEqual(respuesta.get_json(), ejemplo(archivo))

    def test_escaneo_inexistente(self):
        respuesta = self.get("/scans/no-existe/report")

        self.assertEqual(respuesta.status_code, 404)
        self.assertEqual(respuesta.get_json(), ejemplo("error_404.json"))

    def test_sin_token_responde_401(self):
        respuesta = self.client.get("/scans/scan-001/report")

        self.assertEqual(respuesta.status_code, 401)
        self.assertIn("codigo", respuesta.get_json()["error"])

    def test_health_sin_token_para_la_vista_de_salud(self):
        respuesta = self.client.get("/health")  # sin cabecera Authorization

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.get_json()["status"], "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)

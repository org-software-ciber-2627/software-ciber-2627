"""Permisos de las rutas reales, con Identidad y almacenamiento simulados."""
import unittest
from unittest.mock import patch

import requests
from main import app


class TestAuthRoutes(unittest.TestCase):
    READ_ROUTES = (
        "/scans", "/events", "/scan/scan-a", "/scans/scan-a/report",
        "/diff?base=scan-a&target=scan-b",
    )

    def mock(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        self.client = app.test_client()
        self.jobs = {
            key: {"scan_id": key, "target": "192.0.2.10", "profile": "quick",
                  "status": "completed", "created_at": "2026-11-25T10:00:00Z",
                  "events": []}
            for key in ("scan-a", "scan-b")
        }
        self.remote = self.mock("auth.requests.get")
        self.create = self.mock("main.create_job", return_value=self.jobs["scan-a"])
        self.catalog = self.mock("main.list_jobs", return_value=list(self.jobs.values()))
        self.lookup = self.mock("main.get_job", side_effect=self.jobs.get)
        self.report_lookup = self.mock("reports.get_job", side_effect=self.jobs.get)
        self.set_role("analista")

    def set_role(self, role):
        self.remote.return_value.status_code = 200
        self.remote.return_value.json.return_value = {
            "valid": True, "user_id": 1, "username": "usuario-prueba", "role": role,
        }

    def call(self, route, authenticated=True):
        headers = {"Authorization": "Bearer token-prueba"} if authenticated else {}
        if route == "/scan":
            return self.client.post(route, headers=headers,
                                    json={"target": "192.0.2.10", "profile": "quick"})
        return self.client.get(route, headers=headers)

    def assert_denied(self, status, code, authenticated=True):
        for route in (*self.READ_ROUTES, "/scan"):
            with self.subTest(route=route):
                response = self.call(route, authenticated)
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.get_json()["error"]["codigo"], code)
        for operation in (self.create, self.catalog, self.lookup, self.report_lookup):
            operation.assert_not_called()

    def test_all_routes_require_token(self):
        self.assert_denied(401, "UNAUTHENTICATED", authenticated=False)
        self.remote.assert_not_called()

    def test_all_routes_reject_invalid_or_revoked_token(self):
        self.remote.return_value.status_code = 401
        self.assert_denied(401, "UNAUTHENTICATED")

    def test_all_read_routes_allow_each_agreed_role(self):
        for role in ("admin", "analista", "servicio"):
            self.set_role(role)
            for route in self.READ_ROUTES:
                with self.subTest(role=role, route=route):
                    self.assertEqual(self.call(route).status_code, 200)
        self.assertEqual(self.remote.call_count, 15)
        self.create.assert_not_called()

    def test_admin_and_analyst_can_create_scan(self):
        for role in ("admin", "analista"):
            with self.subTest(role=role):
                self.set_role(role)
                self.create.reset_mock()
                self.assertEqual(self.call("/scan").status_code, 200)
                self.create.assert_called_once_with("192.0.2.10", "quick")

    def test_service_cannot_create_scan(self):
        self.set_role("servicio")
        response = self.call("/scan")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"]["codigo"], "FORBIDDEN")
        self.create.assert_not_called()

    def test_unknown_role_has_no_access(self):
        self.set_role("desconocido")
        self.assert_denied(403, "FORBIDDEN")

    def test_identity_http_error_denies_all_routes(self):
        self.remote.return_value.status_code = 500
        self.assert_denied(503, "IDENTITY_UNAVAILABLE")

    def test_identity_network_failure_denies_all_routes(self):
        for error in (requests.Timeout(), requests.ConnectionError()):
            with self.subTest(error=type(error).__name__):
                self.remote.side_effect = error
                self.assert_denied(503, "IDENTITY_UNAVAILABLE")

    def test_health_is_public_even_when_identity_is_down(self):
        self.remote.side_effect = requests.ConnectionError()
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()

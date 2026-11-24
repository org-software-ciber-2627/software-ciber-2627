import unittest
from unittest.mock import Mock, patch

import requests
from flask import Flask, g

from auth import require_roles


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["IDENTITY_URL"] = "http://identidad:80/"
        self.executed = 0

        @self.app.get("/protected")
        @require_roles("admin", "analista")
        def protected():
            self.executed += 1
            return {"user_id": g.identity["user_id"]}

        self.client = self.app.test_client()
        self.identity = {"valid": True, "user_id": 1, "username": "test", "role": "analista"}

    def get(self):
        return self.client.get("/protected", headers={"Authorization": "Bearer test-token"})

    @patch("auth.requests.get")
    def test_missing_or_malformed_header_never_calls_identity(self, remote):
        for header in ("", "Basic abc", "Bearer", "Bearer a b"):
            with self.subTest(header=header):
                response = self.client.get("/protected", headers={"Authorization": header})
                self.assertEqual(response.status_code, 401)
        remote.assert_not_called()
        self.assertEqual(self.executed, 0)

    @patch("auth.requests.get")
    def test_valid_roles_and_remote_validation_without_cache(self, remote):
        for role in ("admin", "analista"):
            remote.return_value = Mock(status_code=200)
            remote.return_value.json.return_value = {**self.identity, "role": role}
            self.assertEqual(self.get().get_json(), {"user_id": 1})
        self.assertEqual(remote.call_count, 2)
        remote.assert_called_with(
            "http://identidad:80/auth/validate",
            headers={"Authorization": "Bearer test-token"},
            timeout=(2, 3), allow_redirects=False,
        )

    @patch("auth.requests.get")
    def test_service_cannot_launch_protected_operation(self, remote):
        remote.return_value = Mock(status_code=200)
        remote.return_value.json.return_value = {**self.identity, "role": "servicio"}
        self.assertEqual(self.get().status_code, 403)
        self.assertEqual(self.executed, 0)

    @patch("auth.requests.get")
    def test_revocation_is_effective_on_next_request(self, remote):
        valid = Mock(status_code=200)
        valid.json.return_value = self.identity
        remote.side_effect = [valid, Mock(status_code=401)]
        self.assertEqual(self.get().status_code, 200)
        self.assertEqual(self.get().status_code, 401)
        self.assertEqual(self.executed, 1)

    @patch("auth.requests.get")
    def test_unavailable_identity_never_grants_access(self, remote):
        for status in (302, 403, 429, 500, 503):
            remote.return_value = Mock(status_code=status)
            self.assertEqual(self.get().status_code, 503)
        for error in (requests.Timeout(), requests.ConnectionError()):
            remote.side_effect = error
            self.assertEqual(self.get().status_code, 503)
        self.assertEqual(self.executed, 0)

    @patch("auth.requests.get")
    def test_invalid_identity_response_never_grants_access(self, remote):
        remote.return_value = Mock(status_code=200)
        for body in ([], {}, {**self.identity, "valid": False},
                     {**self.identity, "user_id": True}, {**self.identity, "role": []}):
            remote.return_value.json.return_value = body
            self.assertEqual(self.get().status_code, 503)
        remote.return_value.json.side_effect = ValueError("invalid json")
        self.assertEqual(self.get().status_code, 503)
        self.assertEqual(self.executed, 0)


if __name__ == "__main__":
    unittest.main()

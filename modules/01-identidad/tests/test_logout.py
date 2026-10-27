import unittest
from src.app import app, db, User  # Ajusta el import si tu estructura difiere ligeramente

class TestLogout(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["JWT_SECRET_KEY"] = "clave-secreta-test"
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            # Creamos un usuario de prueba para obtener un token real
            user = User(username="testuser", email="test@test.com", role="servicio")
            user.set_password("password123")
            db.session.add(user)
            db.session.commit()
            
            resp = self.client.post("/auth/login", json={"username": "testuser", "password": "password123"})
            self.token = resp.get_json()["token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_logout_sin_token(self):
        resp = self.client.post("/auth/logout")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.get_json())

    def test_logout_flujo_completo(self):
        # 1. Logout exitoso (200) y comprobación del mensaje exacto
        resp1 = self.client.post("/auth/logout", headers=self.headers)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.get_json()["message"], "Token revocado")

        # 2. Repetir el uso del token revocado en /validate da 401
        resp2 = self.client.get("/auth/validate", headers=self.headers)
        self.assertEqual(resp2.status_code, 401)
        self.assertIn("error", resp2.get_json())

        # 3. Repetir el uso del token revocado en /secrets da 401
        resp3 = self.client.get("/secrets/dummy", headers=self.headers)
        self.assertEqual(resp3.status_code, 401)
        self.assertIn("error", resp3.get_json())

        # 4. Repetir el logout con el mismo token revocado da 401
        resp4 = self.client.post("/auth/logout", headers=self.headers)
        self.assertEqual(resp4.status_code, 401)
        self.assertIn("error", resp4.get_json())

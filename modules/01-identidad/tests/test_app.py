import os
import secrets
import sys
import tempfile
import time
import unittest
 
import jwt
 
SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)
 
# Antes de importar app: base de datos temporal y entorno limpio, para que ninguna variable
# del desarrollador siembre cuentas o cambie la caducidad durante las pruebas.
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.gettempdir(), "identidad_tests.db").replace("\\", "/")
VARIABLES = (
    "JWT_SECRET_KEY", "AES_KEY", "JWT_EXPIRES_SECONDS", "ADMIN_PASSWORD", "SERVICE_PASSWORD",
    "SECRET_DB_PASSWORD", "SECRET_API_KEY", "SECRET_JWT_SECRET",
)
for _var in VARIABLES:
    os.environ.pop(_var, None)
 
import app as app_module  # noqa: E402
from app import Secret, User, app, db  # noqa: E402
from crypto import encrypt  # noqa: E402
 
USUARIO = {
    "username": "usuario.ejemplo",
    "email": "usuario.ejemplo@ciberurjc.local",
    "password": "contrasena-de-ejemplo",
}
 
 
class BaseTest(unittest.TestCase):
    def setUp(self):
        # Claves aleatorias generadas en cada prueba: no hay secretos escritos en el código.
        self.jwt_secret = secrets.token_hex(32)
        self.aes_key = os.urandom(32)
        app.config.update(TESTING=True, JWT_SECRET_KEY=self.jwt_secret, AES_KEY=self.aes_key)
        with app.app_context():
            db.drop_all()
            db.create_all()
        self.client = app.test_client()
 
    def tearDown(self):
        with app.app_context():
            db.session.remove()
        for var in ("ADMIN_PASSWORD", "SERVICE_PASSWORD", "SECRET_API_KEY"):
            os.environ.pop(var, None)
 
    def registrar(self, **cambios):
        return self.client.post("/auth/register", json={**USUARIO, **cambios})
 
    def login(self, **cuerpo):
        return self.client.post("/auth/login", json=cuerpo)
 
    def contar_usuarios(self):
        with app.app_context():
            return User.query.count()
 
    def decodificar(self, token):
        return jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
 
    def crear_usuario(self, username, role):
        with app.app_context():
            user = User(username=username, email=f"{username}@ciberurjc.local", role=role)
            user.set_password(USUARIO["password"])
            db.session.add(user)
            db.session.commit()
 
    def token_de(self, username):
        r = self.login(username=username, password=USUARIO["password"])
        self.assertEqual(r.status_code, 200)
        return r.get_json()["token"]
 
    def con_token(self, token):
        return {"Authorization": f"Bearer {token}"}
 
 
class TestHealth(BaseTest):
    def test_health_responde_200(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok", "module": "01-identidad"})
 
 
class TestToken(BaseTest):  # AAA-19
    def test_1_jwt_hs256_con_claims_sub_role_iat_exp(self):
        token = self.registrar().get_json()["token"]
        self.assertEqual(jwt.get_unverified_header(token)["alg"], "HS256")
        claims = self.decodificar(token)
        for clave in ("sub", "role", "iat", "exp", "user_id"):
            self.assertIn(clave, claims)
        self.assertEqual(claims["sub"], USUARIO["username"])
        self.assertEqual(claims["role"], "analista")
 
    def test_2_caduca_a_los_30_minutos(self):
        claims = self.decodificar(self.registrar().get_json()["token"])
        self.assertEqual(claims["exp"] - claims["iat"], 30 * 60)
 
    def test_3_sin_clave_en_el_entorno_falla_con_500_pero_health_sigue_vivo(self):
        app.config["JWT_SECRET_KEY"] = None
        r = self.registrar()
        self.assertEqual(r.status_code, 500)
        self.assertEqual(self.contar_usuarios(), 0)  # no se crea usuario si no se puede emitir el token
        self.assertEqual(self.client.get("/health").status_code, 200)  # el CI sigue en verde
 
    def test_4_el_token_no_contiene_datos_sensibles(self):
        token = self.registrar().get_json()["token"]
        claims = self.decodificar(token)
        for prohibido in ("password", "password_hash", "email"):
            self.assertNotIn(prohibido, claims)
        self.assertNotIn(USUARIO["password"], token)
 
    def test_5_el_codigo_no_lleva_claves_ni_contrasenas_por_defecto(self):
        # Guarda para la Definition of Done: el repositorio es público.
        with open(os.path.join(SRC, "app.py"), encoding="utf-8") as f:
            codigo = f.read()
        for fragmento in ("Admin12", "Srv12", "Alice12", "change-me", "sk-prod", "supersecret_", "32-bytes-aes"):
            self.assertNotIn(fragmento, codigo)
 
 
class TestRegistro(BaseTest):  # AAA-18
    def test_1_registro_valido_201_con_token_y_user_sin_password(self):
        r = self.registrar()
        self.assertEqual(r.status_code, 201)
        cuerpo = r.get_json()
        self.assertIn("token", cuerpo)
        self.assertEqual(cuerpo["user"]["username"], USUARIO["username"])
        self.assertEqual(cuerpo["user"]["email"], USUARIO["email"])
        self.assertEqual(cuerpo["user"]["role"], "analista")
        self.assertIsInstance(cuerpo["user"]["id"], int)
        self.assertNotIn("password", cuerpo["user"])
        self.assertNotIn(USUARIO["password"], r.get_data(as_text=True))
 
    def test_2_usuario_o_email_repetidos_409(self):
        self.assertEqual(self.registrar().status_code, 201)
        self.assertEqual(self.registrar(email="otro@ciberurjc.local").status_code, 409)  # mismo username
        self.assertEqual(self.registrar(username="otro.usuario").status_code, 409)  # mismo email
        self.assertEqual(self.contar_usuarios(), 1)
 
    def test_3_datos_invalidos_400_y_no_se_crea_cuenta(self):
        casos = [{"username": ""}, {"password": "corta"}, {"username": "ab"}, {"email": "no-es-un-email"}]
        for caso in casos:
            with self.subTest(caso=caso):
                self.assertEqual(self.registrar(**caso).status_code, 400)
        r = self.client.post("/auth/register", json={"username": "solo.usuario"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/auth/register", data="no es json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.contar_usuarios(), 0)
 
    def test_4_password_guardada_con_hash_y_sal_nunca_en_claro(self):
        self.registrar()
        self.registrar(username="segundo.usuario", email="segundo@ciberurjc.local")
        with app.app_context():
            hashes = [u.password_hash for u in User.query.all()]
        self.assertEqual(len(hashes), 2)
        for h in hashes:
            self.assertNotEqual(h, USUARIO["password"])
            self.assertNotIn(USUARIO["password"], h)
        self.assertNotEqual(hashes[0], hashes[1])  # misma contraseña, hashes distintos: hay sal
 
 
class TestLogin(BaseTest):  # AAA-3
    def setUp(self):
        super().setUp()
        self.assertEqual(self.registrar().status_code, 201)
 
    def test_1_credenciales_correctas_200_con_token_y_user(self):
        r = self.login(username=USUARIO["username"], password=USUARIO["password"])
        self.assertEqual(r.status_code, 200)
        cuerpo = r.get_json()
        self.assertIn("token", cuerpo)
        self.assertEqual(cuerpo["user"]["username"], USUARIO["username"])
 
    def test_2_password_incorrecta_401_sin_token(self):
        r = self.login(username=USUARIO["username"], password="otra-contrasena")
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())
        self.assertNotIn("token", r.get_json())
 
    def test_3_usuario_inexistente_401_con_el_mismo_mensaje(self):
        mala_pass = self.login(username=USUARIO["username"], password="otra-contrasena")
        no_existe = self.login(username="no.existe", password="otra-contrasena")
        self.assertEqual(no_existe.status_code, 401)
        self.assertEqual(mala_pass.get_json(), no_existe.get_json())
 
    def test_4_faltan_campos_400(self):
        self.assertEqual(self.login(username=USUARIO["username"]).status_code, 400)
        self.assertEqual(self.login(password=USUARIO["password"]).status_code, 400)
        self.assertEqual(self.login().status_code, 400)
 
 
class TestValidate(BaseTest):  # adelanta AAA-20
    def token_manual(self, username, exp_delta):
        """Token firmado con la clave de los tests, con los claims que genera Flask-JWT-Extended."""
        ahora = int(time.time())
        claims = {
            "sub": username, "role": "analista", "user_id": 1, "iat": ahora, "nbf": ahora,
            "exp": ahora + exp_delta, "jti": "prueba", "type": "access", "fresh": False,
        }
        return jwt.encode(claims, self.jwt_secret, algorithm="HS256")
 
    def validar(self, token=None):
        cabeceras = self.con_token(token) if token else {}
        return self.client.get("/auth/validate", headers=cabeceras)
 
    def test_1_token_valido_200_con_usuario_y_rol(self):
        token = self.registrar().get_json()["token"]
        r = self.validar(token)
        self.assertEqual(r.status_code, 200)
        cuerpo = r.get_json()
        self.assertIs(cuerpo["valid"], True)
        self.assertIsInstance(cuerpo["user_id"], int)
        self.assertEqual(cuerpo["username"], USUARIO["username"])
        self.assertEqual(cuerpo["role"], "analista")
 
    def test_2_sin_token_401(self):
        r = self.validar()
        self.assertEqual(r.status_code, 401)
        self.assertIs(r.get_json()["valid"], False)
        self.assertIn("error", r.get_json())
 
    def test_3_token_manipulado_401(self):
        token = self.registrar().get_json()["token"]
        r = self.validar(token[:-3] + "abc")
        self.assertEqual(r.status_code, 401)
        self.assertIs(r.get_json()["valid"], False)
 
    def test_4_token_caducado_401(self):
        r = self.validar(self.token_manual(USUARIO["username"], exp_delta=-60))
        self.assertEqual(r.status_code, 401)
 
    def test_5_token_firmado_con_otra_clave_401(self):
        otro = jwt.encode(
            {"sub": "intruso", "role": "servicio", "iat": int(time.time()), "exp": int(time.time()) + 600,
             "jti": "x", "type": "access", "fresh": False},
            secrets.token_hex(32), algorithm="HS256",
        )
        self.assertEqual(self.validar(otro).status_code, 401)
 
 
class TestSecretos(BaseTest):  # adelanta AAA-15/16
    VALOR = "valor-de-prueba-del-secreto"
 
    def setUp(self):
        super().setUp()
        enc, iv, tag = encrypt(self.VALOR, self.aes_key)
        with app.app_context():
            db.session.add(Secret(clave="api_key", valor_encriptado=enc, iv=iv, tag=tag))
            db.session.commit()
        self.crear_usuario("cuenta.servicio", "servicio")
        self.crear_usuario("cuenta.admin", "admin")
        self.crear_usuario("cuenta.analista", "analista")
 
    def leer(self, clave="api_key", token=None):
        cabeceras = self.con_token(token) if token else {}
        return self.client.get(f"/secrets/{clave}", headers=cabeceras)
 
    def test_1_servicio_lee_el_secreto_descifrado_y_sin_cache(self):
        r = self.leer(token=self.token_de("cuenta.servicio"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"clave": "api_key", "valor": self.VALOR})
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")
 
    def test_2_sin_token_401(self):
        self.assertEqual(self.leer().status_code, 401)
 
    def test_3_otros_roles_403_incluido_admin(self):
        for usuario in ("cuenta.analista", "cuenta.admin"):
            with self.subTest(usuario=usuario):
                self.assertEqual(self.leer(token=self.token_de(usuario)).status_code, 403)
 
    def test_4_clave_inexistente_404_y_clave_invalida_400(self):
        token = self.token_de("cuenta.servicio")
        self.assertEqual(self.leer("no_existe", token).status_code, 404)
        self.assertEqual(self.leer("a$b", token).status_code, 400)
 
    def test_5_el_valor_se_guarda_cifrado_en_la_base_de_datos(self):
        with app.app_context():
            guardado = Secret.query.filter_by(clave="api_key").first()
            texto_guardado = guardado.valor_encriptado + guardado.iv + guardado.tag
        self.assertNotIn(self.VALOR, texto_guardado)
 
    def test_6_sin_aes_key_500_sin_filtrar_nada(self):
        token = self.token_de("cuenta.servicio")
        app.config["AES_KEY"] = None
        r = self.leer(token=token)
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(self.VALOR, r.get_data(as_text=True))
 
 
class TestCuentasPrecargadas(BaseTest):
    def sembrar(self):
        with app.app_context():
            app_module.seed()
 
    def test_con_variables_de_entorno_se_crean_admin_y_servicio(self):
        admin_pass, servicio_pass = secrets.token_hex(8), secrets.token_hex(8)
        os.environ["ADMIN_PASSWORD"] = admin_pass
        os.environ["SERVICE_PASSWORD"] = servicio_pass
        self.sembrar()
        r = self.login(username="admin", password=admin_pass)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["user"]["role"], "admin")
        r = self.login(username="servicio", password=servicio_pass)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["user"]["role"], "servicio")
 
    def test_sin_variables_no_se_crea_ninguna_cuenta(self):
        self.sembrar()
        self.assertEqual(self.contar_usuarios(), 0)
        self.assertEqual(self.login(username="admin", password="lo-que-sea").status_code, 401)
 
    def test_los_secretos_de_demostracion_solo_salen_del_entorno_y_van_cifrados(self):
        valor = secrets.token_hex(8)
        os.environ["SECRET_API_KEY"] = valor
        self.sembrar()
        with app.app_context():
            guardado = Secret.query.filter_by(clave="api_key").first()
            self.assertIsNotNone(guardado)
            self.assertNotIn(valor, guardado.valor_encriptado)
            self.assertEqual(Secret.query.count(), 1)  # solo el definido por entorno
 
if __name__ == "__main__":
    unittest.main()
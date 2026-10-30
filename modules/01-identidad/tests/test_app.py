import os
import secrets
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
 
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

class TestLoginRateLimit(BaseTest):  # AAA-67
    MAX_INTENTOS = 5
    IP_A = "192.0.2.10"
    IP_B = "192.0.2.11"

    def setUp(self):
        super().setUp()
        self.assertEqual(self.registrar().status_code, 201)

    def login_desde(self, username, password, ip):
        return self.client.post(
            "/auth/login",
            json={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": ip},
        )

    def test_1_cuatro_fallos_devuelven_401(self):
        for _ in range(4):
            respuesta = self.login_desde(USUARIO["username"], "incorrecta", self.IP_A)
            self.assertEqual(respuesta.status_code, 401)

    def test_2_quinto_fallo_devuelve_429_con_retry_after(self):
        for _ in range(self.MAX_INTENTOS):
            respuesta = self.login_desde(USUARIO["username"], "incorrecta", self.IP_A)
        self.assertEqual(respuesta.status_code, 429)
        self.assertIn("Retry-After", respuesta.headers)
        self.assertGreater(int(respuesta.headers["Retry-After"]), 0)

    def test_3_usuario_inexistente_tambien_se_bloquea_en_el_quinto_fallo(self):
        for _ in range(self.MAX_INTENTOS):
            respuesta = self.login_desde("usuario.inexistente", "incorrecta", self.IP_A)
        self.assertEqual(respuesta.status_code, 429)
        self.assertIn("Retry-After", respuesta.headers)

    def test_4_contrasena_correcta_no_funciona_durante_el_bloqueo(self):
        for _ in range(self.MAX_INTENTOS):
            self.login_desde(USUARIO["username"], "incorrecta", self.IP_A)
        respuesta = self.login_desde(USUARIO["username"], USUARIO["password"], self.IP_A)
        self.assertEqual(respuesta.status_code, 429)
        self.assertNotIn("token", respuesta.get_json())

    def test_5_otra_ip_no_hereda_el_bloqueo(self):
        for _ in range(self.MAX_INTENTOS):
            self.login_desde(USUARIO["username"], "incorrecta", self.IP_A)
        respuesta = self.login_desde(USUARIO["username"], USUARIO["password"], self.IP_B)
        self.assertEqual(respuesta.status_code, 200)
        self.assertIn("token", respuesta.get_json())

    def test_6_otro_usuario_no_hereda_el_bloqueo(self):
        self.crear_usuario("otro.usuario", "analista")
        for _ in range(self.MAX_INTENTOS):
            self.login_desde(USUARIO["username"], "incorrecta", self.IP_A)
        respuesta = self.login_desde("otro.usuario", USUARIO["password"], self.IP_A)
        self.assertEqual(respuesta.status_code, 200)

    def test_7_el_bloqueo_se_guarda_en_audit_log(self):
        for _ in range(self.MAX_INTENTOS):
            self.login_desde("usuario.inexistente", "incorrecta", self.IP_A)
        with app.app_context():
            evento = (
                app_module.AuditLog.query
                .filter_by(
                    event_type="limit_exceeded",
                    username="usuario.inexistente",
                )
                .first()
            )
            self.assertIsNotNone(evento)
            self.assertEqual(evento.source_ip, self.IP_A)

    def test_8_limit_exceeded_se_registra_una_sola_vez(self):
        for _ in range(self.MAX_INTENTOS + 3):
            respuesta = self.login_desde("usuario.inexistente","incorrecta",self.IP_A)
        self.assertEqual(respuesta.status_code, 429)
        with app.app_context():
            eventos = (app_module.AuditLog.query.filter_by(
                event_type="limit_exceeded",
                username="usuario.inexistente",
                source_ip=self.IP_A,
            )
            .count()
            )
            self.assertEqual(eventos, 1)

    def test_9_usuario_largo_tambien_se_bloquea(self):
        username = "u" * 60
        for _ in range(self.MAX_INTENTOS):
            respuesta = self.login_desde(username,"incorrecta",self.IP_A)
        self.assertEqual(respuesta.status_code, 429)
        self.assertIn("Retry-After", respuesta.headers)

 
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
    
    def test_6_cabecera_mal_formada_sin_bearer_retorna_401(self):
        token = self.registrar().get_json()["token"]
        r = self.client.get("/auth/validate", headers={"Authorization": token})
        self.assertEqual(r.status_code, 401)
        self.assertIs(r.get_json()["valid"], False)

    def test_7_token_revocado_via_logout_retorna_401(self):
        token = self.registrar().get_json()["token"]
        self.client.post("/auth/logout", headers=self.con_token(token))
        r = self.client.get("/auth/validate", headers=self.con_token(token))
        self.assertEqual(r.status_code, 401)
        self.assertIs(r.get_json()["valid"], False)

 
 
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

    
class TestLogout(BaseTest):  # AAA-62
    def setUp(self):
        super().setUp()
        self.crear_usuario("servicio.test", "servicio")
        self.headers1 = self.con_token(self.token_de("servicio.test"))
        self.headers2 = self.con_token(self.token_de("servicio.test"))  # segunda sesión

    def test_1_sin_token_da_401_con_error_y_sin_msg(self):
        r = self.client.post("/auth/logout")
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())
        self.assertNotIn("msg", r.get_json())

    def test_2_logout_ok_con_el_mensaje_del_contrato(self):
        r = self.client.post("/auth/logout", headers=self.headers1)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["message"], "Token revocado")

    def test_3_token_revocado_da_401_en_validate_secrets_y_logout(self):
        self.client.post("/auth/logout", headers=self.headers1)
        respuestas = (
            self.client.get("/auth/validate", headers=self.headers1),
            self.client.get("/secrets/api_key", headers=self.headers1),
            self.client.post("/auth/logout", headers=self.headers1),
        )
        for r in respuestas:
            with self.subTest(url=r.request.path):
                self.assertEqual(r.status_code, 401)
                self.assertIn("error", r.get_json())
                self.assertNotIn("msg", r.get_json())

    def test_4_el_logout_solo_revoca_ese_token(self):
        self.client.post("/auth/logout", headers=self.headers1)
        r = self.client.get("/auth/validate", headers=self.headers2)
        self.assertEqual(r.status_code, 200)
        self.assertIs(r.get_json()["valid"], True)

    def token_manual(self, exp_delta=600, clave=None):
        ahora = int(time.time())
        claims = {
            "sub": "servicio.test", "role": "servicio", "user_id": 1, "iat": ahora, "nbf": ahora,
            "exp": ahora + exp_delta, "jti": secrets.token_hex(8), "type": "access", "fresh": False,
        }
        return jwt.encode(claims, clave or self.jwt_secret, algorithm="HS256")

    def test_5_token_manipulado_da_401(self):
        token = self.headers1["Authorization"].split(" ", 1)[1]
        r = self.client.post("/auth/logout", headers=self.con_token(token[:-3] + "abc"))
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())

    def test_6_token_caducado_da_401(self):
        r = self.client.post("/auth/logout", headers=self.con_token(self.token_manual(exp_delta=-60)))
        self.assertEqual(r.status_code, 401)

    def test_7_token_firmado_con_otra_clave_da_401(self):
        r = self.client.post("/auth/logout", headers=self.con_token(self.token_manual(clave=secrets.token_hex(32))))
        self.assertEqual(r.status_code, 401)

    def test_8_cabecera_sin_bearer_da_401(self):
        token = self.headers1["Authorization"].split(" ", 1)[1]
        r = self.client.post("/auth/logout", headers={"Authorization": token})
        self.assertEqual(r.status_code, 401)

    def test_9_tras_el_logout_se_puede_iniciar_sesion_de_nuevo(self):
        self.client.post("/auth/logout", headers=self.headers1)
        nuevo = self.con_token(self.token_de("servicio.test"))
        self.assertEqual(self.client.get("/auth/validate", headers=nuevo).status_code, 200)

    def test_10_el_jti_se_guarda_una_sola_vez_en_la_lista_de_revocados(self):
        token = self.headers1["Authorization"].split(" ", 1)[1]
        jti = self.decodificar(token)["jti"]
        with app.app_context():
            self.assertEqual(app_module.TokenBlocklist.query.count(), 0)
        self.client.post("/auth/logout", headers=self.headers1)
        self.client.post("/auth/logout", headers=self.headers1)  # segundo intento
        with app.app_context():
            self.assertEqual(app_module.TokenBlocklist.query.filter_by(jti=jti).count(), 1)
            self.assertEqual(app_module.TokenBlocklist.query.count(), 1)

    def test_11_el_logout_funciona_con_cualquier_rol(self):
        for rol in ("analista", "admin"):
            with self.subTest(rol=rol):
                self.crear_usuario(f"cuenta.{rol}", rol)
                r = self.client.post("/auth/logout", headers=self.con_token(self.token_de(f"cuenta.{rol}")))
                self.assertEqual(r.status_code, 200)

class TestCors(BaseTest):
    ORIGEN_PERMITIDO = "http://localhost:8007"
    ORIGEN_NO_PERMITIDO = "http://localhost:9999"

    def comprobar_preflight(self, ruta, origen):
        return self.client.options(
            ruta,
            headers={
                "Origin": origen,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )

    def test_1_login_permite_origen_configurado(self):
        response = self.comprobar_preflight("/auth/login",self.ORIGEN_PERMITIDO)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"),self.ORIGEN_PERMITIDO)

    def test_2_register_permite_origen_configurado(self):
        response = self.comprobar_preflight("/auth/register",self.ORIGEN_PERMITIDO)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"),self.ORIGEN_PERMITIDO)

    def test_3_login_rechaza_origen_no_configurado(self):
        response = self.comprobar_preflight("/auth/login",self.ORIGEN_NO_PERMITIDO)
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))

    def test_4_register_rechaza_origen_no_configurado(self):
        response = self.comprobar_preflight("/auth/register",self.ORIGEN_NO_PERMITIDO)
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))

    def test_5_health_no_expone_cabecera_cors(self):
        response = self.client.get("/health",headers={"Origin": self.ORIGEN_PERMITIDO})
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))

    def test_6_secrets_no_expone_cabecera_cors(self):
        response = self.client.get("/secrets/api_key",headers={"Origin": self.ORIGEN_PERMITIDO})
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
         
class TestLogs(BaseTest):
    def setUp(self):
        super().setUp()
        self.crear_usuario("cuenta.admin", "admin")
        self.crear_usuario("cuenta.servicio", "servicio")
        self.crear_usuario("cuenta.analista", "analista")
        # Tokens pre-obtenidos para no contaminar el AuditLog durante los tests
        self.token_admin    = self.token_de("cuenta.admin")
        self.token_servicio = self.token_de("cuenta.servicio")
        self.token_analista = self.token_de("cuenta.analista")
        with app.app_context():
            app_module.AuditLog.query.delete()
            db.session.commit()

    def get_logs(self, token=None):
        cabeceras = self.con_token(token) if token else {}
        return self.client.get("/logs", headers=cabeceras)

    def _insertar_eventos(self, n, event_type="login_ok", result="ok"):
        with app.app_context():
            for _ in range(n):
                db.session.add(app_module.AuditLog(
                    event_type=event_type, result=result,
                    username="cuenta.admin", source_ip="127.0.0.1",
                ))
            db.session.commit()

    def test_1_admin_obtiene_200_con_logs_y_total(self):
        r = self.get_logs(token=self.token_admin)
        self.assertEqual(r.status_code, 200)
        cuerpo = r.get_json()
        self.assertIn("logs", cuerpo)
        self.assertIn("total", cuerpo)
        self.assertIsInstance(cuerpo["logs"], list)
        self.assertIsInstance(cuerpo["total"], int)

    def test_2_servicio_obtiene_200(self):
        r = self.get_logs(token=self.token_servicio)
        self.assertEqual(r.status_code, 200)
        self.assertIn("logs", r.get_json())

    def test_3_analista_obtiene_403(self):
        r = self.get_logs(token=self.token_analista)
        self.assertEqual(r.status_code, 403)
        self.assertIn("error", r.get_json())

    def test_4_sin_token_401(self):
        r = self.get_logs()
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())

    def test_5_token_manipulado_401(self):
        r = self.get_logs(token=self.token_admin[:-3] + "abc")
        self.assertEqual(r.status_code, 401)

    def test_6_estructura_de_cada_entrada(self):
        self._insertar_eventos(1)
        logs = self.get_logs(token=self.token_admin).get_json()["logs"]
        self.assertEqual(len(logs), 1)
        for campo in ("id", "timestamp", "event_type", "result", "username",
                      "role", "source_ip", "source_port", "clave", "enviado"):
            with self.subTest(campo=campo):
                self.assertIn(campo, logs[0])

    def test_7_sin_logs_devuelve_lista_vacia_con_total_cero(self):
        cuerpo = self.get_logs(token=self.token_admin).get_json()
        self.assertEqual(cuerpo["logs"], [])
        self.assertEqual(cuerpo["total"], 0)

    def test_8_total_coincide_con_longitud_de_logs(self):
        self._insertar_eventos(5)
        cuerpo = self.get_logs(token=self.token_admin).get_json()
        self.assertEqual(cuerpo["total"], len(cuerpo["logs"]))

    def test_9_maximo_50_entradas(self):
        self._insertar_eventos(60)
        r = self.get_logs(token=self.token_admin)
        self.assertLessEqual(len(r.get_json()["logs"]), 50)

    def test_10_orden_descendente_por_timestamp(self):
        ahora = datetime.now(timezone.utc).replace(tzinfo=None)
        with app.app_context():
            for delta in (120, 60, 0):
                db.session.add(app_module.AuditLog(
                    event_type="login_ok", result="ok",
                    username="cuenta.admin", source_ip="127.0.0.1",
                    timestamp=ahora - timedelta(seconds=delta),
                ))
            db.session.commit()
        timestamps = [l["timestamp"] for l in self.get_logs(token=self.token_admin).get_json()["logs"]]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))

class TestMinimoPrivilegio(BaseTest):  # AAA-25
    VALOR = "valor-de-prueba-del-secreto"

    def setUp(self):
        super().setUp()
        enc, iv, tag = encrypt(self.VALOR, self.aes_key)
        with app.app_context():
            db.session.add(Secret(clave="api_key", valor_encriptado=enc, iv=iv, tag=tag))
            db.session.commit()
        for nombre, rol in (("cuenta.servicio", "servicio"), ("cuenta.admin", "admin"), ("cuenta.analista", "analista")):
            self.crear_usuario(nombre, rol)

    def get(self, ruta, usuario=None):
        cabeceras = self.con_token(self.token_de(usuario)) if usuario else {}
        return self.client.get(ruta, headers=cabeceras)

    def test_1_el_admin_no_lee_secretos(self):
        r = self.get("/secrets/api_key", "cuenta.admin")
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("valor", r.get_json())
        self.assertNotIn(self.VALOR, r.get_data(as_text=True))

    def test_2_el_analista_no_lee_secretos(self):
        r = self.get("/secrets/api_key", "cuenta.analista")
        self.assertEqual(r.status_code, 403)
        self.assertNotIn(self.VALOR, r.get_data(as_text=True))

    def test_3_solo_el_servicio_lee_secretos(self):
        r = self.get("/secrets/api_key", "cuenta.servicio")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["valor"], self.VALOR)

    def test_4_el_acceso_denegado_queda_auditado_sin_el_valor(self):
        self.get("/secrets/api_key", "cuenta.admin")
        with app.app_context():
            evento = app_module.AuditLog.query.filter_by(event_type="secret_denied").first()
            self.assertIsNotNone(evento)
            self.assertEqual(evento.username, "cuenta.admin")
            self.assertEqual(evento.role, "admin")
            self.assertEqual(evento.clave, "api_key")
            self.assertNotIn(self.VALOR, str(evento.to_dict()))

    def test_5_el_registro_de_auditoria_solo_lo_leen_admin_y_servicio(self):
        self.assertEqual(self.get("/logs", "cuenta.admin").status_code, 200)
        self.assertEqual(self.get("/logs", "cuenta.servicio").status_code, 200)
        self.assertEqual(self.get("/logs", "cuenta.analista").status_code, 403)
        self.assertEqual(self.get("/logs").status_code, 401)

    def test_6_el_registro_no_permite_elegirse_el_rol(self):
        r = self.registrar(role="admin")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["user"]["role"], "analista")
        token = r.get_json()["token"]
        self.assertEqual(self.decodificar(token)["role"], "analista")
        self.assertEqual(self.client.get("/logs", headers=self.con_token(token)).status_code, 403)

    def test_7_el_admin_ve_el_nombre_del_secreto_pero_nunca_su_valor(self):
        self.assertEqual(self.get("/secrets/api_key", "cuenta.servicio").status_code, 200)
        r = self.get("/logs", "cuenta.admin")
        self.assertEqual(r.status_code, 200)
        texto = r.get_data(as_text=True)
        self.assertIn("api_key", texto)
        self.assertNotIn(self.VALOR, texto)

    def test_8_el_servicio_tampoco_ve_el_valor_de_los_secretos_en_los_logs(self):
        self.assertEqual(self.get("/secrets/api_key", "cuenta.servicio").status_code, 200)
        r = self.get("/logs", "cuenta.servicio")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(self.VALOR, r.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()

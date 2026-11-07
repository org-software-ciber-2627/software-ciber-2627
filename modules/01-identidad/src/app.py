"""Módulo 1 · Identidad y secretos: servicio HTTP completo en un único fichero (contrato v1.0.2).

Sprint 1: GET /health, POST /auth/register (AAA-18), POST /auth/login (AAA-3) y emisión del
token (AAA-19). Además incluye GET /auth/validate (adelanta AAA-20) y GET /secrets/{clave}
(adelanta AAA-15/16), porque el contrato ya los publica.

REGLA DE ORO: el repositorio es público. Aquí NO hay claves, contraseñas ni secretos, ni
siquiera «de ejemplo». Todo sale de variables de entorno y, si falta una obligatoria, el
endpoint que la necesita responde 500 (pero /health sigue en 200 para no romper el CI).

Variables de entorno:
  JWT_SECRET_KEY      clave de firma del JWT (obligatoria para registro, login, validate, secrets)
  AES_KEY             clave AES-256 en base64 de 32 bytes aleatorios (obligatoria para /secrets)
  DATABASE_URL        opcional; por defecto sqlite:///identidad.db
  TRUSTED_PROXY_HOPS  opcional; nº de proxies de confianza delante (0 = ninguno, por defecto)
  JWT_EXPIRES_SECONDS opcional; por defecto 1800 (30 minutos, como dice el contrato)
  ADMIN_PASSWORD      opcional; si existe se crea la cuenta "admin"
  SERVICE_PASSWORD    opcional; si existe se crea la cuenta "servicio"
  SECRET_DB_PASSWORD, SECRET_API_KEY, SECRET_JWT_SECRET
                      opcionales; si existen se guardan cifrados como secretos de demostración
"""
import base64
import os
import re
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (JWTManager, create_access_token, decode_token,
                                get_jwt, verify_jwt_in_request)
from flask_jwt_extended.exceptions import JWTExtendedException
from flask_sqlalchemy import SQLAlchemy
from jwt.exceptions import PyJWTError
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from crypto import decrypt, encrypt


class ConfigError(RuntimeError):
    """Falta configuración obligatoria (clave JWT o clave AES)."""


def _load_aes_key():
    """AES_KEY = base64 de exactamente 32 bytes aleatorios. Si falta o no es válida, None."""
    raw = os.environ.get("AES_KEY")
    if not raw:
        return None
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError:
        return None
    return key if len(key) == 32 else None


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")  # sin valor por defecto
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.environ.get("JWT_EXPIRES_SECONDS", 1800))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///identidad.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["AES_KEY"] = _load_aes_key()  # sin valor por defecto

# La IP real del cliente se obtiene de X-Forwarded-For solo cuando hay proxies de confianza
# declarados. Sin proxy (TRUSTED_PROXY_HOPS=0, valor por defecto) se usa la IP de la conexión
# TCP directa: nadie puede falsificar su IP poniendo lo que quiera en X-Forwarded-For.
# Con TRUSTED_PROXY_HOPS=1 (nginx delante), ProxyFix extrae la IP del cliente del header
# X-Forwarded-For y la pone en request.remote_addr, que es lo que usa registrar_evento().
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS)

db  = SQLAlchemy(app)
jwt = JWTManager(app)

# CORS restringido al dashboard (puerto 8007). Solo los endpoints de autenticación lo necesitan.
CORS(app, resources={
    r"/auth/login":    {"origins": "http://localhost:8007"},
    r"/auth/register": {"origins": "http://localhost:8007"},
})

# Roles del contrato (shared/auth-contract.md). Los usuarios registrados nacen como "analista".
ROLES = ("admin", "analista", "servicio")
DEFAULT_ROLE = "analista"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CLAVE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
EVENTOS = ("login_ok", "login_failed", "invalid_user", "secret_read", "secret_denied")


# ── Modelos ───────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(50),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default=DEFAULT_ROLE)

    def set_password(self, pw):   self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def to_dict(self):            return {"id": self.id, "username": self.username, "email": self.email, "role": self.role}


class Secret(db.Model):
    __tablename__    = "secrets"
    id               = db.Column(db.Integer, primary_key=True)
    clave            = db.Column(db.String(100), unique=True, nullable=False)
    valor_encriptado = db.Column(db.Text,        nullable=False)
    iv               = db.Column(db.String(64),  nullable=False)
    tag              = db.Column(db.String(64),  nullable=False)


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"
    id         = db.Column(db.Integer, primary_key=True)
    jti        = db.Column(db.String(36), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class AuditLog(db.Model):
    """Registro de auditoría de seguridad (AAA-57/58). NUNCA guarda contraseñas, tokens ni valores de secretos."""
    __tablename__ = "audit_log"
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))  # UTC
    event_type  = db.Column(db.String(30), nullable=False, index=True)   # ver EVENTOS
    result      = db.Column(db.String(10), nullable=False)               # "ok" | "fail"
    username    = db.Column(db.String(50), nullable=True)
    role        = db.Column(db.String(20), nullable=True)
    source_ip   = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer,    nullable=True)
    clave       = db.Column(db.String(100), nullable=True)               # nombre del secreto, jamás su valor
    enviado     = db.Column(db.Boolean, nullable=False, default=False)   # ya enviado al IDS (AAA-83)

    @property
    def log_id(self):
        """Id estable para el IDS: g1-log-<ms>-<id de fila>. No se repite ni tras reiniciar."""
        ms = int(self.timestamp.replace(tzinfo=timezone.utc).timestamp() * 1000)
        return f"g1-log-{ms}-{self.id}"

    def to_dict(self):
        return {
            "id": self.id, "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": self.event_type, "result": self.result, "username": self.username,
            "role": self.role, "source_ip": self.source_ip, "source_port": self.source_port,
            "clave": self.clave,
            "enviado": self.enviado,
        }


# ── Datos iniciales: SOLO desde variables de entorno, nunca escritos en el código ──

# (username, email, rol, variable de entorno con la contraseña)
CUENTAS = (
    ("admin",    "admin@ciberurjc.local",    "admin",    "ADMIN_PASSWORD"),
    ("servicio", "servicio@ciberurjc.local", "servicio", "SERVICE_PASSWORD"),
)
# (clave del secreto, variable de entorno con su valor)
SECRETOS = (
    ("db_password", "SECRET_DB_PASSWORD"),
    ("api_key",     "SECRET_API_KEY"),
    ("jwt_secret",  "SECRET_JWT_SECRET"),
)


def seed():
    """Crea cuentas y secretos solo si su variable de entorno está definida."""
    for username, email, role, env_var in CUENTAS:
        password = os.environ.get(env_var)
        if password and not User.query.filter_by(username=username).first():
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)

    aes_key = app.config.get("AES_KEY")
    if aes_key:
        for clave, env_var in SECRETOS:
            valor = os.environ.get(env_var)
            if valor and not Secret.query.filter_by(clave=clave).first():
                enc, iv, tag = encrypt(valor, aes_key)
                db.session.add(Secret(clave=clave, valor_encriptado=enc, iv=iv, tag=tag))

    db.session.commit()


with app.app_context():
    db.create_all()
    seed()


@jwt.token_in_blocklist_loader
def _check_token_revoked(_jwt_header, jwt_payload):
    return TokenBlocklist.query.filter_by(jti=jwt_payload["jti"]).first() is not None


# ── Ayudantes ─────────────────────────────────────────────────────────────────

# Hash de relleno: se usa cuando el usuario no existe para que el login tarde parecido
# exista o no la cuenta (evita enumerar usuarios por tiempo de respuesta).
_DUMMY_HASH = generate_password_hash("contrasena-de-relleno")


def require_jwt_key():
    if not app.config.get("JWT_SECRET_KEY"):
        raise ConfigError("La variable de entorno JWT_SECRET_KEY no está definida")


def get_aes_key():
    key = app.config.get("AES_KEY")
    if not key:
        raise ConfigError("AES_KEY no está definida o no es base64 de 32 bytes")
    return key


def registrar_evento(event_type, result, username=None, role=None, clave=None):
    """Guarda un evento de auditoría. Un fallo aquí nunca debe tumbar el endpoint."""
    try:
        puerto = request.environ.get("REMOTE_PORT")
        db.session.add(AuditLog(
            event_type=event_type, result=result,
            username=username[:50] if username else None, role=role, clave=clave,
            # Con TRUSTED_PROXY_HOPS>0, ProxyFix ya resolvió request.remote_addr a la IP
            # real del cliente leyendo X-Forwarded-For. Con TRUSTED_PROXY_HOPS=0 se usa la
            # IP de la conexión TCP directa y X-Forwarded-For se ignora (no es falsificable).
            source_ip=request.remote_addr or "unknown",
            source_port=int(puerto) if puerto and str(puerto).isdigit() and not TRUSTED_PROXY_HOPS else None,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


def crear_token(user):
    """JWT HS256 con sub (nombre de usuario), role, user_id, iat y exp (30 min por defecto)."""
    require_jwt_key()
    return create_access_token(
        identity=user.username, additional_claims={"role": user.role, "user_id": user.id}
    )


def validar_registro(data):
    """Devuelve un mensaje de error o None si los datos son válidos."""
    if not isinstance(data, dict):
        return "El cuerpo debe ser un JSON con username, email y password"
    username, password, email = data.get("username"), data.get("password"), data.get("email")
    if not all(isinstance(v, str) and v for v in (username, password, email)):
        return "Faltan campos obligatorios: username, email y password"
    if not 3 <= len(username) <= 50:
        return "El username debe tener entre 3 y 50 caracteres"
    if not 8 <= len(password) <= 128:
        return "La contraseña debe tener entre 8 y 128 caracteres"
    if not EMAIL_RE.match(email):
        return "El email no tiene un formato válido"
    return None


def check_auth(required_roles=None):
    """Valida el JWT del request. Misma lógica que expone GET /auth/validate."""
    require_jwt_key()
    try:
        verify_jwt_in_request()
    except (JWTExtendedException, PyJWTError):
        return None, ("Token inválido, expirado o ausente", 401)
    claims = get_jwt()
    if required_roles and claims.get("role") not in required_roles:
        return None, ("El rol no tiene permiso para este recurso", 403)
    return claims, None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/register")
def register():
    require_jwt_key()  # falla antes de tocar la base de datos si falta la clave
    data = request.get_json(silent=True)
    error = validar_registro(data)
    if error:
        return jsonify(error=error), 400
    user = User(username=data["username"], email=data["email"].lower())
    user.set_password(data["password"])
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="El usuario o el email ya existen"), 409
    return jsonify(token=crear_token(user), user=user.to_dict()), 201


@app.post("/auth/login")
def login():
    require_jwt_key()
    data = request.get_json(silent=True)
    username = data.get("username") if isinstance(data, dict) else None
    password = data.get("password") if isinstance(data, dict) else None
    if not (isinstance(username, str) and username and isinstance(password, str) and password):
        return jsonify(error="Falta el nombre de usuario o la contraseña"), 400
    user = User.query.filter_by(username=username).first()
    if user is None:
        check_password_hash(_DUMMY_HASH, password)  # tiempo parecido exista o no la cuenta
        registrar_evento("invalid_user", "fail", username=username)
        return jsonify(error="Usuario o contraseña incorrectos"), 401
    if not user.check_password(password):
        registrar_evento("login_failed", "fail", username=user.username, role=user.role)
        return jsonify(error="Usuario o contraseña incorrectos"), 401
    registrar_evento("login_ok", "ok", username=user.username, role=user.role)
    return jsonify(token=crear_token(user), user=user.to_dict()), 200


@app.post("/auth/logout")
def logout():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify(error="Token inválido, expirado o ausente"), 401
    raw_token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = decode_token(raw_token)
    except Exception:
        return jsonify(error="Token inválido, expirado o ausente"), 401
    jti = decoded["jti"]
    if not TokenBlocklist.query.filter_by(jti=jti).first():
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
    return jsonify(message="Token revocado"), 200


@app.get("/auth/validate")
def validate():
    claims, err = check_auth()
    if err:
        return jsonify(error=err[0], valid=False), err[1]
    return jsonify(valid=True, user_id=claims.get("user_id"), username=claims["sub"], role=claims.get("role"))


# ── Secretos ──────────────────────────────────────────────────────────────────

@app.get("/secrets/<clave>")
def leer_secreto(clave):
    claims, err = check_auth(required_roles=["servicio"])
    if err:
        # solo se audita si hay token válido (403); sin token (401) no sabemos quién es
        if err[1] == 403:
            registrar_evento("secret_denied", "fail", username=get_jwt().get("sub"),
                             role=get_jwt().get("role"), clave=clave[:100])
        return jsonify(error=err[0]), err[1]
    if not CLAVE_RE.match(clave):
        return jsonify(error="Clave no válida"), 400
    secret = Secret.query.filter_by(clave=clave).first()
    if not secret:
        registrar_evento("secret_denied", "fail", username=claims["sub"], role=claims.get("role"), clave=clave)
        return jsonify(error="No se encontró un secreto para esa clave"), 404
    aes_key = get_aes_key()
    try:
        valor = decrypt(secret.valor_encriptado, secret.iv, secret.tag, aes_key)
    except (ValueError, KeyError):
        return jsonify(error="No se pudo descifrar el secreto"), 500
    registrar_evento("secret_read", "ok", username=claims["sub"], role=claims.get("role"), clave=clave)
    respuesta = jsonify(clave=clave, valor=valor)
    respuesta.headers["Cache-Control"] = "no-store"  # contrato: nunca en caché
    return respuesta


# ── Logs ─────────────────────────────────────────────────────────────────────

@app.get("/logs")
def get_logs():
    claims, err = check_auth(required_roles=["admin", "servicio"])
    if err:
        return jsonify(error=err[0]), err[1]
    logs = (
        AuditLog.query
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )
    return jsonify(logs=[l.to_dict() for l in logs], total=len(logs))


# ── Salud y errores ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify(status="ok", module="01-identidad")


@app.errorhandler(ConfigError)
def config_error(_e):
    return jsonify(error="Error de configuración del servidor"), 500


@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify(error=e.description), e.code


@app.errorhandler(Exception)
def unexpected_error(_e):
    return jsonify(error="Error no esperado"), 500

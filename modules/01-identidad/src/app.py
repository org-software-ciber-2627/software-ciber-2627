import base64
import os
import re
 
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, verify_jwt_in_request
from flask_jwt_extended.exceptions import JWTExtendedException
from flask_sqlalchemy import SQLAlchemy
from jwt.exceptions import PyJWTError
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
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
 
db = SQLAlchemy(app)
jwt = JWTManager(app)
 
# Roles del contrato (shared/auth-contract.md). Los usuarios registrados nacen como "analista".
ROLES = ("admin", "analista", "servicio")
DEFAULT_ROLE = "analista"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CLAVE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
 
 
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
        return jsonify(error="Usuario o contraseña incorrectos"), 401
    if not user.check_password(password):
        return jsonify(error="Usuario o contraseña incorrectos"), 401
    return jsonify(token=crear_token(user), user=user.to_dict()), 200
 
 
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
        return jsonify(error=err[0]), err[1]
    if not CLAVE_RE.match(clave):
        return jsonify(error="Clave no válida"), 400
    secret = Secret.query.filter_by(clave=clave).first()
    if not secret:
        return jsonify(error="No se encontró un secreto para esa clave"), 404
    aes_key = get_aes_key()
    try:
        valor = decrypt(secret.valor_encriptado, secret.iv, secret.tag, aes_key)
    except (ValueError, KeyError):
        return jsonify(error="No se pudo descifrar el secreto"), 500
    respuesta = jsonify(clave=clave, valor=valor)
    respuesta.headers["Cache-Control"] = "no-store"  # contrato: nunca en caché
    return respuesta
 
 
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
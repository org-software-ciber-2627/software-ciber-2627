"""Validación remota con Identidad; nunca se verifica ni registra el JWT localmente."""

import os
from functools import wraps

import requests
from flask import current_app, g, jsonify, request

import threading
import time
import requests

def _error(codigo, mensaje, status):
    return jsonify(error={"codigo": codigo, "mensaje": mensaje}), status


def require_roles(*roles):
    """Protege una ruta con los roles indicados y valida en G1 en cada petición.

    Configurar IDENTITY_URL en Flask o en el entorno (http://identidad:80
    dentro de Docker). Por defecto utiliza Identidad local en el puerto 8001.
    El usuario validado queda disponible en g.identity.
    """
    if not roles or not set(roles) <= {"admin", "analista", "servicio"}:
        raise ValueError("Es necesario indicar roles válidos")

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return _error("UNAUTHENTICATED", "Se requiere un token Bearer", 401)

            base_url = current_app.config.get(
                "IDENTITY_URL", os.environ.get("IDENTITY_URL", "http://localhost:8001")
            )
            try:
                response = requests.get(
                    base_url.rstrip("/") + "/auth/validate",
                    headers={"Authorization": "Bearer " + parts[1]},
                    timeout=(2, 3),
                    allow_redirects=False,
                )
                if response.status_code == 401:
                    return _error("UNAUTHENTICATED", "Token inválido, caducado o revocado", 401)
                if response.status_code != 200:
                    return _error("IDENTITY_UNAVAILABLE", "No se pudo validar la identidad", 503)
                identity = response.json()
            except (requests.exceptions.RequestException, ValueError):
                return _error("IDENTITY_UNAVAILABLE", "No se pudo validar la identidad", 503)

            if (
                not isinstance(identity, dict)
                or identity.get("valid") is not True
                or type(identity.get("user_id")) is not int
                or not isinstance(identity.get("username"), str)
                or not identity["username"].strip()
                or not isinstance(identity.get("role"), str)
            ):
                return _error("IDENTITY_UNAVAILABLE", "Respuesta de Identidad incompatible", 503)
            if identity["role"] not in roles:
                return _error("FORBIDDEN", "El rol no tiene permiso para esta operación", 403)

            g.identity = identity
            return view(*args, **kwargs)

        return wrapped

    return decorator

# Gestor del token de servicio proporcionado por el grupo 1 (Identidad)
def _build_login_url() -> str:
    identity_url = os.environ.get("IDENTITY_URL", "http://localhost:8001").rstrip("/")
    if identity_url.endswith("/auth/login"):
        return identity_url
    return f"{identity_url}/auth/login"


class ServiceTokenManager:
    """Gestiona el JWT de la cuenta de servicio (svc-escaner) para publicar al SIEM."""

    def __init__(
        self,
        login_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        refresh_after_seconds: int | None = None,
    ):
        self.login_url = login_url or _build_login_url()
        self.username = username if username is not None else os.environ.get("SIEM_SVC_USER", "svc-escaner")
        self.password = password if password is not None else os.environ.get("SIEM_SVC_PASSWORD", "")
        raw_refresh = (
            refresh_after_seconds
            if refresh_after_seconds is not None
            else int(os.environ.get("SIEM_TOKEN_REFRESH_SECONDS", "1500"))
        )
        self.refresh_after_seconds = max(1, int(raw_refresh))
        self._token: str | None = None
        self._obtained_at: float = 0.0
        self._lock = threading.Lock()

    def get_token(self) -> str:
        """Devuelve el token en caché o hace login si falta o está próximo a caducar (30 min)."""
        with self._lock:
            now = time.monotonic()
            if (
                self._token is not None
                and (now - self._obtained_at) < self.refresh_after_seconds
            ):
                return self._token
            return self._do_login_locked(now)

    def refresh_token(self) -> str:
        """Fuerza un nuevo login en G1 (por ejemplo, al recibir un 401 del SIEM)."""
        with self._lock:
            return self._do_login_locked(time.monotonic())

    def _do_login_locked(self, now: float) -> str:
        resp = requests.post(
            self.login_url,
            json={"username": self.username, "password": self.password},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=3,
        )
        resp.raise_for_status()
        payload = resp.json()
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("Respuesta de /auth/login sin 'token' válido")
        self._token = token
        self._obtained_at = now
        return self._token

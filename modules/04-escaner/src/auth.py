"""Validación remota con Identidad; nunca se verifica ni registra el JWT localmente."""

import os
from functools import wraps

import requests
from flask import current_app, g, jsonify, request


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

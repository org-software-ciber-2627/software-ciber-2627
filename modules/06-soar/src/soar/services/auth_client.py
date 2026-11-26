from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("soar.auth")

# Identidad bloquea 15 min una cuenta de servicio tras 5 logins fallidos: tras un 401 o 429 se espera
DEFAULT_RETRY_SECONDS = 300.0
REJECTED_LOGIN_CODES = {401, 429}


def _retry_seconds_from_env() -> float:
    raw = os.getenv("SOAR_AUTH_RETRY_SECONDS", "")
    if not raw.strip():
        return DEFAULT_RETRY_SECONDS
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if value < 0:
        logger.warning("SOAR_AUTH_RETRY_SECONDS no es válido (%r); se usan %s s", raw, DEFAULT_RETRY_SECONDS)
        return DEFAULT_RETRY_SECONDS
    return value


class AuthClientError(RuntimeError):
    """Error al obtener o renovar el token de servicio frente al Módulo 01."""


class IdentityAuthClient:
    """Cliente de autenticación de servicio (svc-soar) contra el Módulo 01 (Identidad)."""

    def __init__(
        self,
        auth_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token_ttl_seconds: float = 25 * 60,  # margen seguro frente a los 30 min del Módulo 01
        timeout: float = 10.0,
        retry_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        raw_url = auth_url if auth_url is not None else (os.getenv("AUTH_URL") or os.getenv("IDENTITY_URL") or "")
        self.auth_url = raw_url.rstrip("/")
        self.username = username if username is not None else os.getenv("SOAR_SERVICE_USER", "svc-soar")
        self.password = password if password is not None else os.getenv("SOAR_SERVICE_PASSWORD", "")
        self.token_ttl_seconds = token_ttl_seconds
        self.timeout = timeout
        self.retry_seconds = retry_seconds if retry_seconds is not None else _retry_seconds_from_env()
        self._clock = clock
        self._token: str | None = None
        self._expires_at: float = 0.0
        # Momento hasta el que no se repite un login rechazado (401 o 429)
        self._login_blocked_until: float = 0.0

    @property
    def is_configured(self) -> bool:
        return bool(self.auth_url and self.username and self.password)

    def invalidate_token(self) -> None:
        """Descarta el token en caché para forzar un nuevo login en la siguiente petición."""
        self._token = None
        self._expires_at = 0.0

    def get_token(self, force_refresh: bool = False) -> str:
        """Devuelve un token JWT válido, autenticándose contra Módulo 01 si es necesario."""
        if not force_refresh and self._token and self._clock() < self._expires_at:
            return self._token

        if not self.is_configured:
            raise AuthClientError(
                "Faltan variables de entorno de autenticación (AUTH_URL, SOAR_SERVICE_USER, SOAR_SERVICE_PASSWORD)"
            )

        remaining = self._login_blocked_until - self._clock()
        if remaining > 0:
            # No se llama a Identidad: otro login fallido acercaría la cuenta al bloqueo de 15 min
            raise AuthClientError(
                f"Login de {self.username} rechazado hace poco por Módulo 01; "
                f"no se reintenta hasta dentro de {int(remaining) + 1} s (SOAR_AUTH_RETRY_SECONDS)"
            )

        payload = json.dumps({"username": self.username, "password": self.password}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.auth_url}/auth/login",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            logger.error("Error HTTP (%s) al autenticar %s contra Módulo 01", error.code, self.username)
            if error.code in REJECTED_LOGIN_CODES:
                self._login_blocked_until = self._clock() + self.retry_seconds
                logger.warning("No se reintentará el login de %s durante %s s", self.username, self.retry_seconds)
            raise AuthClientError(f"Login rechazado por Módulo 01 (HTTP {error.code})") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            logger.error("Error de red o formato al autenticar contra Módulo 01: %s", error)
            raise AuthClientError("No se pudo conectar con el Módulo 01 de Identidad") from error

        token = _extract_token(body)
        if not token:
            raise AuthClientError("La respuesta de /auth/login no contiene un token válido")

        self._token = token
        self._expires_at = self._clock() + self.token_ttl_seconds
        self._login_blocked_until = 0.0
        logger.info("Token de servicio renovado correctamente para %s", self.username)
        return token


def _extract_token(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in ("access_token", "token", "jwt"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
from __future__ import annotations

import http.client
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Callable

from pydantic import ValidationError

from soar.models.identity import AuthenticatedUser

logger = logging.getLogger("soar.auth")


class UnauthorizedError(Exception):
    """El token fue rechazado por Identidad."""


class IdentityUnavailableError(Exception):
    """No se pudo completar la validación del token con Identidad."""


def identity_url_from_env() -> str:
    return (os.getenv("AUTH_URL") or os.getenv("IDENTITY_URL") or "").rstrip("/")


class TokenValidator:
    def __init__(
        self,
        identity_url: str,
        timeout: float = 5.0,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        self.identity_url = identity_url.rstrip("/")
        self.timeout = timeout
        self.opener = opener

    def validate(self, token: str) -> AuthenticatedUser:
        request = urllib.request.Request(
            f"{self.identity_url}/auth/validate",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                status = response.status
                raw_body = response.read()
        except urllib.error.HTTPError as error:
            if error.code == 401:
                logger.warning("Identidad rechazó el token (HTTP 401)")
                raise UnauthorizedError from error
            logger.error("Identidad devolvió HTTP %s al validar token", error.code)
            raise IdentityUnavailableError from error
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.HTTPException,
        ) as error:
            logger.error(
                "Error de transporte al validar token con Identidad (%s)",
                type(error).__name__,
            )
            raise IdentityUnavailableError from error

        if status == 401:
            logger.warning("Identidad rechazó el token (HTTP 401)")
            raise UnauthorizedError
        if status != 200:
            logger.error("Identidad devolvió HTTP %s al validar token", status)
            raise IdentityUnavailableError

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            logger.error(
                "Identidad devolvió JSON inválido al validar token (%s)",
                type(error).__name__,
            )
            raise IdentityUnavailableError from error

        if isinstance(payload, dict) and payload.get("valid") is False:
            logger.warning("Identidad indicó que el token no es válido")
            raise UnauthorizedError
        if (
            not isinstance(payload, dict)
            or payload.get("valid") is not True
            or not isinstance(payload.get("username"), str)
            or not payload["username"].strip()
            or not isinstance(payload.get("role"), str)
            or not payload["role"].strip()
        ):
            logger.error("Respuesta de validación de Identidad incompleta o inválida")
            raise IdentityUnavailableError

        try:
            return AuthenticatedUser(
                user_id=payload.get("user_id"),
                username=payload["username"].strip(),
                role=payload["role"].strip(),
            )
        except ValidationError as error:
            logger.error(
                "Identidad devolvió datos de usuario inválidos (%s)",
                type(error).__name__,
            )
            raise IdentityUnavailableError from error

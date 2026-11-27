#!/usr/bin/env python3
"""SEM-134: tokens validos, invalidos y expirados contra el G1 real del Compose.

Desde el contrato 0.5.0 (SEM-142) la cuenta compartida `servicio` ya no puede leer
/alerts, asi que la prueba registra un analista de usar y tirar en Identidad.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

SIEM = os.environ.get("SIEM_URL", "http://localhost:8005")
IDENTITY = os.environ.get("IDENTITY_PUBLIC_URL", "http://localhost:8001")


def required(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"Falta la variable de entorno {name}")
    return value


def call(url, method="GET", token=None, body=None):
    """Devuelve (codigo HTTP, cuerpo)."""
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def register_analyst():
    """Crea un analista de prueba (rol `analista`) y devuelve (usuario, contrasena, id)."""
    username = f"ci-analista-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(24)
    status, body = call(f"{IDENTITY}/auth/register", "POST",
                        body={"username": username, "password": password,
                              "email": f"{username}@ciberurjc.local"})
    if status != 201:
        sys.exit(f"Registro del analista de prueba fallido: HTTP {status}")
    return username, password, json.loads(body)["user"]["id"]


def login(username, password):
    status, body = call(f"{IDENTITY}/auth/login", "POST",
                        body={"username": username, "password": password})
    if status != 200:
        sys.exit(f"Login en Identidad fallido: HTTP {status}")
    return json.loads(body)["token"]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign(key, lifetime, username, user_id):
    """JWT HS256 como los de G1; con lifetime negativo ya nace expirado."""
    now = int(time.time())
    claims = {"sub": username, "role": "analista", "user_id": user_id,
              "iat": now - 3600, "nbf": now - 3600, "exp": now + lifetime,
              "jti": str(uuid.uuid4()), "type": "access", "fresh": False}
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    content = f"{head}.{b64(json.dumps(claims).encode())}"
    return f"{content}.{b64(hmac.new(key.encode(), content.encode(), hashlib.sha256).digest())}"


def tamper(token):
    """Cambia el primer caracter de la firma."""
    content, signature = token.rsplit(".", 1)
    return f"{content}.{'B' if signature[0] == 'A' else 'A'}{signature[1:]}"


def main():
    key = required("JWT_SECRET_KEY")

    username, password, user_id = register_analyst()
    valid = login(username, password)
    revoked = login(username, password)
    if call(f"{IDENTITY}/auth/logout", "POST", token=revoked)[0] != 200:
        sys.exit("No se pudo revocar el token de prueba")

    cases = [
        ("token valido", valid, 200),
        ("sin token", None, 401),
        ("cadena cualquiera", "no-es-un-jwt", 401),
        ("firma alterada", tamper(valid), 401),
        ("firmado con otra clave", sign("otra-clave-que-no-es-la-de-identidad", 600, username, user_id), 401),
        ("control: firmado en la prueba, vigente", sign(key, 600, username, user_id), 200),
        ("expirado", sign(key, -600, username, user_id), 401),
        ("revocado con logout", revoked, 401),
    ]

    failures = 0
    for name, token, expected in cases:
        status, body = call(f"{SIEM}/alerts", token=token)
        ok = status == expected
        if status == 401:
            ok = ok and json.loads(body)["error"]["code"] == "UNAUTHENTICATED"
        if token and token.encode() in body:
            ok = False
        failures += not ok
        # Nunca se imprime el token ni el cuerpo de la respuesta.
        print(f"{'OK ' if ok else 'MAL'} {name}: esperado {expected}, obtenido {status}")

    logs = subprocess.run(["docker", "compose", "logs", "--no-color", "siem", "identidad"],
                          capture_output=True, text=True, errors="replace", check=True).stdout
    if not logs.strip():
        sys.exit("Los logs estan vacios: no se puede comprobar que no haya fugas")
    leaked = [name for name, token, _ in cases if token and token.count(".") == 2 and token in logs]
    for name in leaked:
        print(f"MAL el token del caso '{name}' aparece en los logs")
    if not leaked:
        print("OK  ningun token aparece en los logs de siem ni identidad")

    sys.exit(1 if failures or leaked else 0)


if __name__ == "__main__":
    main()

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { login, getToken } from "../src/auth-client.js";
import { respuesta, definirGlobal, storageEnMemoria } from "./helpers.js";

let llamadas;

const usuarioEjemplo = {
  id: 1,
  username: "ana",
  email: "ana@example.com",
  role: "analista",
};

function prepararEntorno(resp) {
  llamadas = [];

  definirGlobal("sessionStorage", storageEnMemoria());

  definirGlobal("fetch", async (url, opciones) => {
    llamadas.push({ url, opciones });
    return resp;
  });
}

beforeEach(() => {
  prepararEntorno(respuesta(200, {
    token: "jwt-token-ejemplo",
    user: usuarioEjemplo,
  }));
});

// ---------------------------------------------------------- Login correcto

test("login envía POST /auth/login con usuario y contraseña", async () => {
  await login("ana", "password123");

  assert.equal(llamadas.length, 1);
  assert.equal(llamadas[0].url, "/api/identidad/auth/login");
  assert.equal(llamadas[0].opciones.method, "POST");
  assert.equal(
    llamadas[0].opciones.headers["Content-Type"],
    "application/json"
  );

  assert.deepEqual(
    JSON.parse(llamadas[0].opciones.body),
    { username: "ana", password: "password123" }
  );
});

test("login correcto guarda el token y devuelve los datos del usuario", async () => {
  const resultado = await login("ana", "password123");

  assert.deepEqual(resultado, {
    ok: true,
    user: usuarioEjemplo,
  });

  assert.equal(getToken(), "jwt-token-ejemplo");
});

// ---------------------------------------------------------- Errores HTTP

test("login con credenciales incorrectas (401) devuelve invalid_credentials", async () => {
  prepararEntorno(respuesta(401, {
    error: "Credenciales incorrectas",
  }));

  const resultado = await login("ana", "incorrecta");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "invalid_credentials",
  });

  assert.equal(getToken(), null);
});

test("login con petición incorrecta (400) devuelve bad_request", async () => {
  prepararEntorno(respuesta(400, {
    error: "Faltan campos obligatorios",
  }));

  const resultado = await login("", "");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "bad_request",
  });
});

test("login con demasiados intentos (429) devuelve rate_limited y Retry-After", async () => {
  prepararEntorno({
    status: 429,
    headers: {
      get: (nombre) => nombre === "Retry-After" ? "60" : null,
    },
  });

  const resultado = await login("ana", "password123");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "rate_limited",
    retryAfter: 60,
  });
});

test("login con 429 sin Retry-After válido devuelve retryAfter null", async () => {
  prepararEntorno({
    status: 429,
    headers: {
      get: () => null,
    },
  });

  const resultado = await login("ana", "password123");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "rate_limited",
    retryAfter: null,
  });
});

test("login con error del servidor (500) devuelve server", async () => {
  prepararEntorno(respuesta(500, {
    error: "Error interno",
  }));

  const resultado = await login("ana", "password123");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "server",
  });
});

// ---------------------------------------------------------- Fallo de red

test("login cuando falla la conexión devuelve server sin lanzar error", async () => {
  definirGlobal("fetch", async () => {
    throw new TypeError("Failed to fetch");
  });

  const resultado = await login("ana", "password123");

  assert.deepEqual(resultado, {
    ok: false,
    reason: "server",
  });

  assert.equal(getToken(), null);
});
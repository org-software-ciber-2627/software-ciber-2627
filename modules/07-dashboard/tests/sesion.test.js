// DASHG7-86: pruebas de cierre de sesión y caducidad del token.
// Sustituyen a las comprobaciones de texto en Pester (DASHG7-86.Tests.ps1): aquí se ejecuta
// auth-client.js con fetch y sessionStorage simulados y se comprueba el comportamiento.
import test from "node:test";
import assert from "node:assert/strict";
import {
  cargarSiemAlert,
  definirGlobal,
  montarPagina,
  respuesta,
  storageEnMemoria,
} from "./helpers.js";
import { getToken, logout, requireSession, validate } from "../src/auth-client.js";

/** Prepara los globales mínimos del navegador y devuelve las llamadas a fetch y las redirecciones. */
function entorno({ token = "token-valido", fetchImpl } = {}) {
  const llamadas = [];
  const redirecciones = [];
  definirGlobal("sessionStorage", storageEnMemoria(token ? { token, logged_in: "true" } : {}));
  definirGlobal("document", { getElementById: () => null });
  definirGlobal("window", { location: { replace: (destino) => redirecciones.push(destino) } });
  definirGlobal("fetch", async (url, opciones) => {
    llamadas.push({ url: String(url), opciones });
    return fetchImpl(url, opciones);
  });
  return { llamadas, redirecciones };
}

const sesionValida = { valid: true, user_id: 1, username: "ana", role: "analista" };

// ---------------------------------------------------------------- Cierre de sesión

test("logout borra el token y el indicador logged_in de sessionStorage", async () => {
  entorno({ fetchImpl: async () => respuesta(200, { message: "ok" }) });
  await logout();
  assert.equal(getToken(), null);
  assert.equal(sessionStorage.getItem("logged_in"), null);
});

test("logout avisa a Identidad con POST /auth/logout y el token en Authorization", async () => {
  const { llamadas } = entorno({ fetchImpl: async () => respuesta(200, {}) });
  await logout();
  assert.equal(llamadas.length, 1);
  assert.equal(llamadas[0].url, "/api/identidad/auth/logout");
  assert.equal(llamadas[0].opciones.method, "POST");
  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer token-valido");
});

test("logout sin token no llama a Identidad", async () => {
  const { llamadas } = entorno({ token: null, fetchImpl: async () => respuesta(200, {}) });
  await logout();
  assert.equal(llamadas.length, 0);
});

test("con Identidad caída, logout no lanza error y el token queda descartado", async () => {
  entorno({
    fetchImpl: async () => {
      throw new TypeError("fetch failed");
    },
  });
  await assert.doesNotReject(logout());
  assert.equal(getToken(), null);
});

// ---------------------------------------------------------------- Validación y caducidad

test("validate sin token devuelve no_token y no llama a Identidad", async () => {
  const { llamadas } = entorno({ token: null, fetchImpl: async () => respuesta(200, sesionValida) });
  assert.deepEqual(await validate(), { valid: false, reason: "no_token" });
  assert.equal(llamadas.length, 0);
});

test("validate consulta /auth/validate con el token y devuelve los datos de la sesión", async () => {
  const { llamadas } = entorno({ fetchImpl: async () => respuesta(200, sesionValida) });
  const resultado = await validate();
  assert.equal(llamadas[0].url, "/api/identidad/auth/validate");
  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer token-valido");
  assert.deepEqual(resultado, { valid: true, ...sesionValida });
});

test("requireSession con sesión válida no redirige y devuelve la sesión", async () => {
  const { redirecciones } = entorno({ fetchImpl: async () => respuesta(200, sesionValida) });
  const sesion = await requireSession();
  assert.equal(sesion.username, "ana");
  assert.deepEqual(redirecciones, []);
});

test("requireSession sin token redirige al login", async () => {
  const { redirecciones } = entorno({ token: null, fetchImpl: async () => respuesta(200, sesionValida) });
  assert.equal(await requireSession(), null);
  assert.deepEqual(redirecciones, ["login.html"]);
});

test("token caducado (validate 401): se borra el token y se redirige al login", async () => {
  const { redirecciones } = entorno({ fetchImpl: async () => respuesta(401, { error: "invalid_token" }) });
  assert.equal(await requireSession(), null);
  assert.equal(getToken(), null);
  assert.deepEqual(redirecciones, ["login.html"]);
});

test("con Identidad caída (validate 500) se redirige al login sin borrar el token", async () => {
  const { redirecciones } = entorno({ fetchImpl: async () => respuesta(500, {}) });
  assert.equal(await requireSession(), null);
  assert.equal(getToken(), "token-valido");
  assert.deepEqual(redirecciones, ["login.html"]);
});

// ---------------------------------------------------------------- Botón "Cerrar Sesión"

test("el botón «Cerrar Sesión» descarta el token y pide POST /auth/logout", async () => {
  const llamadas = [];
  const { dom } = montarPagina({
    fetchImpl: async (url, opciones) => {
      llamadas.push({ url: String(url), metodo: opciones?.method ?? "GET" });
      return respuesta(200, []);
    },
  });
  await cargarSiemAlert();

  dom.window.document.getElementById("logout-btn").click();
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

  assert.equal(sessionStorage.getItem("token"), null);
  assert.ok(
    llamadas.some((c) => c.url === "/api/identidad/auth/logout" && c.metodo === "POST"),
    "debe llamar a POST /api/identidad/auth/logout"
  );
});

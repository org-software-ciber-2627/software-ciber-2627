// Pruebas de src/SIEM-client.js (DASHG7-22 / DASHG7-50 / DASHG7-67): cliente de GET /alerts con token.
// getAlerts() no lanza errores: siempre devuelve { estado, datos, mensaje } (ver src/api-estado.js).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { alerta, respuesta, definirGlobal, storageEnMemoria } from "./helpers.js";
import { getAlerts } from "../src/SIEM-client.js";

let llamadas;

function simularFetch(resp) {
  llamadas = [];
  definirGlobal("fetch", async (url, opciones) => {
    llamadas.push({ url, opciones });
    return resp;
  });
}

beforeEach(() => {
  definirGlobal("sessionStorage", storageEnMemoria());
  definirGlobal("window", { location: { href: "" } });
});

test("con alertas devuelve estado ok y la lista data.alerts", async () => {
  const alertas = [alerta({ alert_id: "A1" }), alerta({ alert_id: "A2" })];
  simularFetch(respuesta(200, { alerts: alertas }));

  assert.deepEqual(await getAlerts(), { estado: "ok", datos: alertas, mensaje: "" });
});

test("con {alerts: []} devuelve estado vacio", async () => {
  simularFetch(respuesta(200, { alerts: [] }));

  const r = await getAlerts();

  assert.equal(r.estado, "vacio");
  assert.deepEqual(r.datos, []);
});

test("una respuesta sin la lista de alertas es un error", async () => {
  simularFetch(respuesta(200, {}));

  const r = await getAlerts();

  assert.equal(r.estado, "error");
  assert.match(r.mensaje, /Respuesta inesperada al consultar el SIEM/);
});

test("envía el token guardado en sessionStorage como Bearer", async () => {
  sessionStorage.setItem("token", "abc123");
  simularFetch(respuesta(200, { alerts: [] }));

  await getAlerts();

  assert.equal(llamadas.length, 1);
  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer abc123");
});

test("sin token en sessionStorage usa el token de prueba", async () => {
  simularFetch(respuesta(200, { alerts: [] }));

  await getAlerts();

  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer token-de-prueba");
});

test("401 borra el token y redirige al login", async () => {
  sessionStorage.setItem("token", "caducado");
  simularFetch(respuesta(401, {}));

  const r = await getAlerts();

  assert.equal(r.estado, "sin_permiso");
  assert.equal(sessionStorage.getItem("token"), null);
  assert.equal(window.location.href, "login.html");
});

test("403 devuelve sin_permiso y no redirige", async () => {
  simularFetch(respuesta(403, {}));

  const r = await getAlerts();

  assert.equal(r.estado, "sin_permiso");
  assert.match(r.mensaje, /No tienes permiso para consultar el SIEM/);
  assert.equal(window.location.href, "");
});

test("otro error HTTP (500) devuelve un error con el código", async () => {
  simularFetch(respuesta(500, {}));

  const r = await getAlerts();

  assert.equal(r.estado, "error");
  assert.match(r.mensaje, /500/);
});

test("un fallo de red devuelve un error en lugar de lanzarlo", async () => {
  definirGlobal("fetch", async () => {
    throw new TypeError("Failed to fetch");
  });

  const r = await getAlerts();

  assert.equal(r.estado, "error");
  assert.match(r.mensaje, /No se pudo conectar con el SIEM/);
});

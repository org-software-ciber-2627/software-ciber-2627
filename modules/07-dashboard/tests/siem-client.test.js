// Pruebas de src/SIEM-client.js (DASHG7-22 / DASHG7-50): cliente de GET /alerts con token.
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
});

test("devuelve la lista data.alerts de la respuesta", async () => {
  const alertas = [alerta({ alert_id: "A1" }), alerta({ alert_id: "A2" })];
  simularFetch(respuesta(200, { alerts: alertas }));

  assert.deepEqual(await getAlerts(), alertas);
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

for (const status of [401, 403]) {
  test(`${status} se traduce en el error "Sin permiso"`, async () => {
    simularFetch(respuesta(status, {}));

    await assert.rejects(getAlerts(), { message: "Sin permiso" });
  });
}

test("otro error HTTP (500) lanza un error con el código", async () => {
  simularFetch(respuesta(500, {}));

  await assert.rejects(getAlerts(), { message: "500" });
});

test("un fallo de red se propaga al llamador", async () => {
  definirGlobal("fetch", async () => {
    throw new TypeError("Failed to fetch");
  });

  await assert.rejects(getAlerts(), TypeError);
});

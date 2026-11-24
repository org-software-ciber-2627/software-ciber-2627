import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { getAlertById } from "../src/SIEM-client.js";
import { alerta, respuesta, definirGlobal, storageEnMemoria } from "./helpers.js";

let llamadas;
let redirecciones;

function prepararEntorno(resp) {
  llamadas = [];
  redirecciones = [];

  definirGlobal("sessionStorage", storageEnMemoria({ token: "token-valido" }));

  definirGlobal("window", {
    location: {
      replace: (destino) => redirecciones.push(destino),
    },
  });

  definirGlobal("fetch", async (url, opciones) => {
    llamadas.push({ url, opciones });
    return resp;
  });
}

beforeEach(() => {
  prepararEntorno(respuesta(200, alerta()));
});

test("consulta el detalle mediante GET /alerts/{id} y envía el token", async () => {
  const resultado = await getAlertById("SIEM-ALERT-001");

  assert.equal(llamadas.length, 1);
  assert.equal(llamadas[0].url, "/api/siem/alerts/SIEM-ALERT-001");
  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer token-valido");
  assert.deepEqual(resultado, alerta());
});

test("codifica el identificador de la alerta en la URL", async () => {
  await getAlertById("alerta/ejemplo 1");

  assert.equal(
    llamadas[0].url,
    "/api/siem/alerts/alerta%2Fejemplo%201"
  );
});

test("404 devuelve el error ALERT_NOT_FOUND del contrato", async () => {
  prepararEntorno(respuesta(404, {
    error: {
      code: "ALERT_NOT_FOUND",
      message: "The requested alert does not exist",
    },
  }));

  await assert.rejects(
    getAlertById("no-existe"),
    { message: "ALERT_NOT_FOUND" }
  );
});

test("401 elimina el token y redirige al login", async () => {
  prepararEntorno(respuesta(401, {}));

  await assert.rejects(
    getAlertById("SIEM-ALERT-001"),
    { message: "Sesión caducada o rechazada" }
  );

  assert.equal(sessionStorage.getItem("token"), null);
  assert.deepEqual(redirecciones, ["login.html"]);
});

test("403 devuelve un error de permisos sin redirigir", async () => {
  prepararEntorno(respuesta(403, {}));

  await assert.rejects(
    getAlertById("SIEM-ALERT-001"),
    { message: "Sin permiso" }
  );

  assert.deepEqual(redirecciones, []);
});

test("un error HTTP 500 devuelve el código de estado", async () => {
  prepararEntorno(respuesta(500, {}));

  await assert.rejects(
    getAlertById("SIEM-ALERT-001"),
    { message: "Error 500" }
  );
});
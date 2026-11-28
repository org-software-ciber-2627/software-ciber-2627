// DASHG7-133: pruebas de contrato contra lo que PUBLICAN los proveedores.
// Estas pruebas leen las carpetas contract/ de los otros módulos (no copias nuestras). Si G1, G5 o G6
// cambian un campo o un código de estado de su contrato, el job contract-tests falla.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { definirGlobal, respuesta, storageEnMemoria } from "./helpers.js";
import { getAlerts, getAlertById } from "../src/SIEM-client.js";
import { getSOARIncidents } from "../src/SOAR-client.js";
import { login, validate, logout } from "../src/auth-client.js";

// Normaliza los saltos de línea: en Windows Git puede dejar los ficheros con CRLF.
const leer = (ruta) => readFileSync(new URL(ruta, import.meta.url), "utf8").replace(/\r\n/g, "\n");
const SIEM = new URL("../../05-siem/contract/openapi.json", import.meta.url);
const IDENTIDAD = "../../01-identidad/contract/openapi.yaml";
const SOAR = "../../06-soar/contract/README.md";

let llamadas;
beforeEach(() => {
  llamadas = [];
  definirGlobal("sessionStorage", storageEnMemoria({ token: "t" }));
  definirGlobal("window", { location: { replace() {}, href: "" } });
});
const servir = (resp) =>
  definirGlobal("fetch", async (url, opciones) => { llamadas.push({ url, opciones }); return resp; });

// ------------------------------------------------------------------ SIEM (G5): openapi.json

const siem = JSON.parse(readFileSync(SIEM, "utf8"));
const ejemplo = (ruta, metodo, codigo) =>
  siem.paths[ruta][metodo].responses[codigo].content["application/json"].example;

test("SIEM: GET /alerts y GET /alerts/{id} siguen declarando los códigos que usa el Dashboard", () => {
  assert.ok(siem.paths["/alerts"].get.responses["200"], "/alerts ya no declara 200");
  assert.ok(siem.paths["/alerts/{id}"].get.responses["200"], "/alerts/{id} ya no declara 200");
  assert.ok(siem.paths["/alerts/{id}"].get.responses["404"], "/alerts/{id} ya no declara 404");
});

test("SIEM: SIEM-client.js interpreta el ejemplo de GET /alerts del contrato", async () => {
  const cuerpo = ejemplo("/alerts", "get", "200");
  servir(respuesta(200, cuerpo));

  const r = await getAlerts();

  assert.equal(r.estado, "ok");
  assert.equal(r.datos.length, cuerpo.alerts.length);
  for (const a of r.datos) {
    for (const campo of ["alert_id", "timestamp", "source", "severity", "title"]) {
      assert.ok(a[campo], `${a.alert_id}: el contrato ya no trae "${campo}"`);
    }
  }
});

test("SIEM: SIEM-client.js interpreta el ejemplo de GET /alerts/{id} y el 404 del contrato", async () => {
  const alerta = ejemplo("/alerts/{id}", "get", "200");
  servir(respuesta(200, alerta));
  assert.deepEqual(await getAlertById(alerta.alert_id), alerta);
  assert.equal(llamadas[0].url, `/api/siem/alerts/${encodeURIComponent(alerta.alert_id)}`);

  servir(respuesta(404, ejemplo("/alerts/{id}", "get", "404")));
  await assert.rejects(() => getAlertById("NO-EXISTE"), /ALERT_NOT_FOUND/);
});

// ------------------------------------------------------------------ Identidad (G1): openapi.yaml
// Sin dependencia de YAML: se leen del texto los códigos de cada operación y los campos required.

const yaml = leer(IDENTIDAD);

function codigos(ruta, metodo) {
  const lineas = yaml.split("\n");
  let i = lineas.findIndex((l) => l === `  ${ruta}:`);
  assert.ok(i >= 0, `Identidad ya no declara ${ruta}`);
  i = lineas.findIndex((l, n) => n > i && l === `    ${metodo}:`);
  const fin = lineas.findIndex((l, n) => n > i && /^( {2}\S| {4}(get|post|put|delete|patch):)/.test(l));
  return lineas.slice(i, fin < 0 ? undefined : fin)
    .map((l) => l.match(/^ {8}'(\d{3})':/)?.[1]).filter(Boolean);
}

function requeridos(esquema) {
  const lineas = yaml.split("\n");
  const i = lineas.findIndex((l) => l === `    ${esquema}:`);
  assert.ok(i >= 0, `Identidad ya no declara el esquema ${esquema}`);
  const r = lineas.findIndex((l, n) => n > i && l === "      required:");
  const campos = [];
  for (let n = r + 1; /^ {8}- /.test(lineas[n] ?? ""); n++) campos.push(lineas[n].replace(/^ {8}- /, "").trim());
  return campos;
}

for (const [ruta, metodo, esperados] of [
  ["/auth/login", "post", ["200", "400", "401", "429"]],
  ["/auth/validate", "get", ["200", "401"]],
  ["/auth/logout", "post", ["200", "401"]],
]) {
  test(`Identidad: ${metodo.toUpperCase()} ${ruta} sigue declarando ${esperados.join(", ")}`, () => {
    const declarados = codigos(ruta, metodo);
    for (const c of esperados) assert.ok(declarados.includes(c), `${ruta} ya no declara ${c}`);
  });
}

test("Identidad: las respuestas siguen trayendo los campos que lee auth-client.js", () => {
  for (const c of ["token", "user"]) assert.ok(requeridos("LoginResponse").includes(c), `login sin "${c}"`);
  for (const c of ["id", "username", "email", "role"]) assert.ok(requeridos("UserResponse").includes(c), `user sin "${c}"`);
  for (const c of ["valid", "user_id", "username", "role"]) assert.ok(requeridos("ValidateResponse").includes(c), `validate sin "${c}"`);
});

test("Identidad: auth-client.js funciona con una respuesta que tiene justo los campos del contrato", async () => {
  const usuario = Object.fromEntries(requeridos("UserResponse").map((c) => [c, c === "id" ? 1 : `${c}-x`]));
  const sesion = Object.fromEntries(requeridos("ValidateResponse").map((c) => [c, c === "valid" ? true : c === "user_id" ? 1 : `${c}-x`]));

  servir(respuesta(200, { token: "jwt", user: usuario }));
  assert.deepEqual(await login("u", "p"), { ok: true, user: usuario });

  servir(respuesta(200, sesion));
  assert.deepEqual(await validate(), { valid: true, ...sesion });

  servir(respuesta(200, { message: "Token revocado" }));
  await logout();
  assert.equal(llamadas.at(-1).url, "/api/identidad/auth/logout");
});

// ------------------------------------------------------------------ SOAR (G6): contract/README.md
// G6 no publica JSON suelto: sus ejemplos están en bloques ```json del README, y los campos en la tabla.

const readme = leer(SOAR);
const ejemplosSoar = [...readme.matchAll(/```json\n([\s\S]*?)```/g)]
  .map((m) => { try { return JSON.parse(m[1]); } catch { return null; } })
  .filter((e) => e && !Array.isArray(e) && Object.hasOwn(e, "incident_id"));
const camposSoar = [...readme.split("### Campos")[1].split(/\n#{2,3} /)[0].matchAll(/^\| `(\w+)` \|/gm)].map((m) => m[1]);

test("SOAR: el README de G6 sigue publicando ejemplos de incidente y la tabla de campos", () => {
  assert.ok(ejemplosSoar.length >= 2, "no hay ejemplos de incidente en el README del SOAR");
  assert.ok(camposSoar.includes("incident_id") && camposSoar.includes("status"), "la tabla de campos ha cambiado");
});

test("SOAR: cada ejemplo del contrato trae todos los campos de la tabla", () => {
  for (const e of ejemplosSoar) {
    for (const campo of camposSoar) assert.ok(Object.hasOwn(e, campo), `${e.incident_id ?? e.id}: falta "${campo}"`);
  }
});

test("SOAR: SOAR-client.js interpreta los ejemplos del contrato", async () => {
  servir(respuesta(200, ejemplosSoar));

  const r = await getSOARIncidents();

  assert.equal(r.estado, "ok");
  assert.equal(r.datos.length, ejemplosSoar.length);
});

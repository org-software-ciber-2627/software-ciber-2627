// DASHG7-32 / DASHG7-138 / DASHG7-139: actividad reciente del honeypot.
// El cliente pide GET /events al SIEM (por el proxy de nginx) y la vista pinta solo los eventos con
// origen honeypot. Los datos de ejemplo son los del propio contrato del honeypot
// (modules/03-honeypot/contract/examples): si el productor cambia un ejemplo, estas pruebas lo notan.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { definirGlobal, montarPagina, respuesta, storageEnMemoria } from "./helpers.js";
import { getHoneypotActivity, actividadHoneypot, MAX_EVENTOS } from "../src/HONEYPOT-client.js";

const DIR_EJEMPLOS = new URL("../../03-honeypot/contract/examples/", import.meta.url);
const ejemplos = readdirSync(DIR_EJEMPLOS)
  .filter((f) => f.endsWith(".json"))
  .flatMap((f) => {
    const datos = JSON.parse(readFileSync(new URL(f, DIR_EJEMPLOS), "utf8"));
    return Array.isArray(datos) ? datos : [datos];
  });

const evento = (extra = {}) => ({
  event_id: "EV-1",
  timestamp: "2026-10-12T14:30:00Z",
  source: "honeypot",
  event_type: "fuerza_bruta",
  severity: "medium",
  title: "t",
  description: "d",
  details: { source_ip: "10.0.0.1", service: "honeypot-web", username: null, credential: null, command: null },
  ...extra,
});

const escaner = () => evento({ event_id: "SC-1", source: "scanner", event_type: "vulnerability_detected" });
const pausa = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };

let importaciones = 0;
/** Monta index.html, simula fetch y ejecuta HONEYPOT-actividad.js (cada import con parámetro distinto, para evitar la caché). */
async function cargarVista(fetchImpl, opciones = {}) {
  const pagina = montarPagina({ fetchImpl, ...opciones });
  const url = new URL("../src/HONEYPOT-actividad.js", import.meta.url);
  url.searchParams.set("prueba", String(++importaciones));
  await import(url.href);
  await pausa();
  const d = pagina.dom.window.document;
  return {
    ...pagina,
    filas: () => [...d.querySelectorAll("#honeypot-body tr")].map((tr) => [...tr.querySelectorAll("td")].map((td) => td.textContent)),
    aviso: () => d.getElementById("error-honeypot"),
    tbody: () => d.getElementById("honeypot-body"),
  };
}

const eventos = (lista) => respuesta(200, { events: lista, next_offset: null, next: null });

// ------------------------------------------------------------------ Cliente

test("los ejemplos del contrato del honeypot cumplen lo que necesita la vista", () => {
  assert.ok(ejemplos.length > 0);
  for (const e of ejemplos) {
    assert.equal(e.source, "honeypot");
    assert.ok(!Number.isNaN(Date.parse(e.timestamp)), `${e.event_id}: timestamp`);
    assert.equal(typeof e.details.source_ip, "string", `${e.event_id}: details.source_ip`);
    assert.equal(typeof e.details.service, "string", `${e.event_id}: details.service`);
    assert.equal(typeof e.event_type, "string", `${e.event_id}: event_type`);
  }
});

test("pide GET /events por el proxy del SIEM y envía el token", async () => {
  const llamadas = [];
  definirGlobal("sessionStorage", storageEnMemoria({ token: "token-valido" }));
  definirGlobal("fetch", async (url, opciones) => { llamadas.push({ url, opciones }); return eventos(ejemplos); });

  const r = await getHoneypotActivity();

  assert.equal(llamadas.length, 1);
  assert.equal(llamadas[0].url, "/api/siem/events?limit=500&offset=0");
  assert.equal(llamadas[0].opciones.headers.Authorization, "Bearer token-valido");
  assert.equal(r.estado, "ok");
});

test("se queda solo con los eventos del honeypot, el más reciente primero", async () => {
  const antiguo = evento({ event_id: "A", timestamp: "2026-10-12T10:00:00Z" });
  const reciente = evento({ event_id: "B", timestamp: "2026-10-12T18:00:00Z" });
  definirGlobal("sessionStorage", storageEnMemoria());
  definirGlobal("fetch", async () => eventos([antiguo, escaner(), reciente]));

  const r = await getHoneypotActivity();

  assert.deepEqual(r.datos.map((e) => e.event_id), ["B", "A"]);
});

test(`muestra como máximo los ${MAX_EVENTOS} eventos más recientes`, () => {
  const muchos = Array.from({ length: MAX_EVENTOS + 5 }, (_, i) =>
    evento({ event_id: `E${i}`, timestamp: new Date(Date.UTC(2026, 9, 12, 10, i)).toISOString() }));

  const lista = actividadHoneypot({ events: muchos });

  assert.equal(lista.length, MAX_EVENTOS);
  assert.equal(lista[0].event_id, `E${MAX_EVENTOS + 4}`);
});

test("una respuesta sin la lista events es una respuesta inesperada", async () => {
  definirGlobal("sessionStorage", storageEnMemoria());
  definirGlobal("fetch", async () => respuesta(200, { error: "x" }));

  const r = await getHoneypotActivity();

  assert.equal(r.estado, "error");
  assert.match(r.mensaje, /Respuesta inesperada al consultar el SIEM/);
});

// ------------------------------------------------------------------ Vista con datos de ejemplo

test("muestra hora, IP de origen, servicio señuelo y tipo de intento de cada evento", async () => {
  const vista = await cargarVista(async () => eventos(ejemplos));
  const filas = vista.filas();

  assert.equal(filas.length, ejemplos.length);
  const tipos = filas.map((f) => f[3]);
  assert.ok(tipos.includes("Fuerza bruta"));
  assert.ok(tipos.includes("Escaneo"));
  assert.ok(tipos.includes("Credenciales por defecto"));
  assert.ok(tipos.includes("Intento de acceso"));

  for (const e of ejemplos) {
    const fila = filas.find((f) => f[0] === new Date(e.timestamp).toLocaleString() && f[1] === e.details.source_ip);
    assert.ok(fila, `${e.event_id}: no hay fila con su hora e IP`);
    assert.equal(fila[2], e.details.service);
  }
  assert.equal(vista.aviso().style.display, "none");
});

test("el evento más reciente aparece primero", async () => {
  const vista = await cargarVista(async () => eventos(ejemplos));
  const masReciente = [...ejemplos].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];

  assert.equal(vista.filas()[0][1], masReciente.details.source_ip);
  assert.equal(vista.filas()[0][0], new Date(masReciente.timestamp).toLocaleString());
});

test("ignora los eventos de otros orígenes", async () => {
  const vista = await cargarVista(async () => eventos([escaner(), evento()]));

  assert.equal(vista.filas().length, 1);
});

test("no muestra usuario, contraseña ni comando del atacante", async () => {
  const secreto = evento({ details: { source_ip: "10.0.0.1", service: "ftp", username: "root", credential: "Password123", command: "rm -rf /" } });
  const vista = await cargarVista(async () => eventos([secreto]));
  const texto = vista.tbody().textContent;

  for (const dato of ["root", "Password123", "rm -rf /"]) assert.ok(!texto.includes(dato), `aparece "${dato}"`);
});

test("escapa el HTML de los campos que controla el atacante (XSS)", async () => {
  const malicioso = evento({
    event_type: '<img src=x onerror="alert(1)">',
    details: { source_ip: "<script>alert(1)</script>", service: '<b onmouseover="x()">ssh</b>' },
  });
  const vista = await cargarVista(async () => eventos([malicioso]));

  assert.equal(vista.tbody().querySelectorAll("img, script, b").length, 0);
  assert.ok(vista.tbody().textContent.includes("<script>alert(1)</script>"));
});

test("un evento sin details se pinta con guiones, sin romper la tabla", async () => {
  const vista = await cargarVista(async () => eventos([evento({ details: null })]));

  assert.deepEqual(vista.filas()[0].slice(1, 3), ["—", "—"]);
});

// ------------------------------------------------------------------ Estados de error y vacío

test("sin eventos muestra «Sin datos.» con el estilo de vacío, no de error", async () => {
  const vista = await cargarVista(async () => eventos([]));

  assert.equal(vista.filas().length, 0);
  assert.equal(vista.aviso().textContent, "Sin datos.");
  assert.equal(vista.aviso().className, "aviso-vacio");
  assert.equal(vista.aviso().style.display, "block");
});

test("si el SIEM solo tiene eventos de otros orígenes también muestra «Sin datos.»", async () => {
  const vista = await cargarVista(async () => eventos([escaner()]));

  assert.equal(vista.aviso().textContent, "Sin datos.");
  assert.equal(vista.aviso().className, "aviso-vacio");
});

for (const [codigo, texto] of [[500, "(código 500)"], [503, "(código 503)"]]) {
  test(`un ${codigo} del SIEM muestra un error y no una tabla vacía sin explicación`, async () => {
    const vista = await cargarVista(async () => respuesta(codigo, { error: { code: "X", message: "x" } }));

    assert.equal(vista.filas().length, 0);
    assert.match(vista.aviso().textContent, new RegExp(`Error al consultar el SIEM \\${texto.replace(")", "\\)")}`));
    assert.equal(vista.aviso().className, "aviso-error");
  });
}

test("sin conexión con el SIEM muestra el mensaje de conexión", async () => {
  const vista = await cargarVista(async () => { throw new TypeError("Failed to fetch"); });

  assert.equal(vista.aviso().textContent, "No se pudo conectar con el SIEM.");
  assert.equal(vista.aviso().className, "aviso-error");
});

test("un 403 muestra el aviso de permiso", async () => {
  const vista = await cargarVista(async () => respuesta(403, {}));

  assert.equal(vista.aviso().textContent, "No tienes permiso para consultar el SIEM.");
});

test("un 401 borra el token y lleva al login", async () => {
  let ventana;
  const vista = await cargarVista(async () => {
    ventana = { location: { href: "" } };
    definirGlobal("window", ventana);
    return respuesta(401, {});
  });

  assert.equal(sessionStorage.getItem("token"), null);
  assert.equal(ventana.location.href, "login.html");
  assert.equal(vista.filas().length, 0);
});

// ------------------------------------------------------------------ Refresco

test("se refresca cada 30 s y recupera la tabla tras un error", async () => {
  let fallar = true;
  const vista = await cargarVista(async () => (fallar ? respuesta(500, {}) : eventos(ejemplos)));
  assert.equal(vista.filas().length, 0);

  const refresco = vista.temporizadores.find((t) => t.ms === 30000);
  assert.ok(refresco, "no hay un temporizador de 30 s");

  fallar = false;
  await refresco.fn();
  await pausa();

  assert.equal(vista.filas().length, ejemplos.length);
  assert.equal(vista.aviso().style.display, "none");
});

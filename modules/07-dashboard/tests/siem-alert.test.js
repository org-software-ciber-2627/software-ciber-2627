// Pruebas de src/SIEM-alert.js sobre el index.html real (DASHG7-22 listado y DASHG7-25 refresco).
import { test } from "node:test";
import assert from "node:assert/strict";
import { alerta, respuesta, montarPagina, cargarSiemAlert, filasTabla } from "./helpers.js";

const visible = (dom, id) => dom.window.document.getElementById(id).style.display !== "none";

test("ordena por severidad (critical > high > medium > low)", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () =>
      respuesta(200, {
        alerts: [
          alerta({ title: "baja", severity: "low" }),
          alerta({ title: "crítica", severity: "critical" }),
          alerta({ title: "media", severity: "medium" }),
          alerta({ title: "alta", severity: "high" }),
        ],
      }),
  });
  await cargarSiemAlert();

  assert.deepEqual(filasTabla(dom).map((f) => f.titulo), ["crítica", "alta", "media", "baja"]);
});

test("a igual severidad, la alerta más reciente va primero", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () =>
      respuesta(200, {
        alerts: [
          alerta({ title: "antigua", timestamp: "2026-09-22T10:00:00Z" }),
          alerta({ title: "reciente", timestamp: "2026-09-29T10:00:00Z" }),
          alerta({ title: "intermedia", timestamp: "2026-09-25T10:00:00Z" }),
        ],
      }),
  });
  await cargarSiemAlert();

  assert.deepEqual(filasTabla(dom).map((f) => f.titulo), ["reciente", "intermedia", "antigua"]);
});

test("muestra severidad, título y módulo de origen, y aplica la clase de color", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () =>
      respuesta(200, {
        alerts: [alerta({ severity: "high", title: "Fuerza bruta", source: "honeypot" })],
      }),
  });
  await cargarSiemAlert();

  const [fila] = filasTabla(dom);
  assert.equal(fila.severidad, "high");
  assert.equal(fila.clase, "sev high");
  assert.equal(fila.titulo, "Fuerza bruta");
  assert.equal(fila.origen, "honeypot");
});

test("una severidad desconocida se pinta sin clase de color y va al final", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () =>
      respuesta(200, {
        alerts: [
          alerta({ title: "rara", severity: "otra" }),
          alerta({ title: "baja", severity: "low" }),
        ],
      }),
  });
  await cargarSiemAlert();

  const filas = filasTabla(dom);
  assert.deepEqual(filas.map((f) => f.titulo), ["baja", "rara"]);
  assert.equal(filas[1].clase, "sev ");
});

test("escapa el HTML de los campos para evitar inyección (XSS)", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () =>
      respuesta(200, {
        alerts: [alerta({ title: '<img src=x onerror="alert(1)">', source: "<b>ids</b>" })],
      }),
  });
  await cargarSiemAlert();

  const doc = dom.window.document;
  assert.equal(doc.querySelectorAll("#tabla tbody img, #tabla tbody b").length, 0);
  const [fila] = filasTabla(dom);
  assert.equal(fila.titulo, '<img src=x onerror="alert(1)">');
  assert.equal(fila.origen, "<b>ids</b>");
});

test("con datos correctos muestra la tabla, oculta el error y actualiza la hora", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () => respuesta(200, { alerts: [alerta()] }),
  });
  await cargarSiemAlert();

  assert.equal(visible(dom, "tabla"), true);
  assert.equal(visible(dom, "error"), false);
  assert.notEqual(dom.window.document.getElementById("hora-actualizacion").textContent, "Cargando...");
});

test("si el SIEM falla muestra el mensaje de error y oculta la tabla", async () => {
  const { dom } = montarPagina({ fetchImpl: async () => respuesta(500, {}) });
  await cargarSiemAlert();

  assert.equal(visible(dom, "error"), true);
  assert.equal(visible(dom, "tabla"), false);
  assert.match(dom.window.document.getElementById("error").textContent, /Error al consultar el SIEM \(código 500\)/);
});

test("si no hay conexión (fetch rechaza) también muestra el error", async () => {
  const { dom } = montarPagina({
    fetchImpl: async () => {
      throw new TypeError("Failed to fetch");
    },
  });
  await cargarSiemAlert();

  assert.equal(visible(dom, "error"), true);
  assert.equal(visible(dom, "tabla"), false);
});

test("programa el refresco cada 30 s y al repetirlo vuelve a pedir las alertas", async () => {
  let peticiones = 0;
  const { dom, temporizadores } = montarPagina({
    fetchImpl: async () => {
      peticiones++;
      return respuesta(200, { alerts: [alerta({ title: `petición ${peticiones}` })] });
    },
  });
  await cargarSiemAlert();

  assert.equal(temporizadores.length, 1);
  assert.equal(temporizadores[0].ms, 30000);
  assert.equal(peticiones, 1);

  temporizadores[0].fn(); // simula que pasan 30 s
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

  assert.equal(peticiones, 2);
  assert.deepEqual(filasTabla(dom).map((f) => f.titulo), ["petición 2"]);
});

test("tras un error, el siguiente refresco recupera la tabla", async () => {
  let fallar = true;
  const { dom, temporizadores } = montarPagina({
    fetchImpl: async () => (fallar ? respuesta(500, {}) : respuesta(200, { alerts: [alerta()] })),
  });
  await cargarSiemAlert();
  assert.equal(visible(dom, "error"), true);

  fallar = false;
  temporizadores[0].fn();
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

  assert.equal(visible(dom, "error"), false);
  assert.equal(visible(dom, "tabla"), true);
  assert.equal(filasTabla(dom).length, 1);
});

// DASHG7-85 / DASHG7-20: cargar() valida la sesión en cada refresco. jsdom escribe
// "Not implemented: navigation" al redirigir al login; es normal y no afecta al resultado.
test("con la sesión caducada (validate 401) borra el token y no pide las alertas", async () => {
  let peticionesDatos = 0;
  const { dom } = montarPagina({
    token: "caducado",
    validateImpl: respuesta(401, { valid: false }),
    fetchImpl: async () => {
      peticionesDatos++;
      return respuesta(200, { alerts: [alerta()] });
    },
  });
  await cargarSiemAlert();

  assert.equal(sessionStorage.getItem("token"), null);
  assert.equal(peticionesDatos, 0);
  assert.equal(filasTabla(dom).length, 0);
});

test("con Identidad caída (validate 500) no pide las alertas", async () => {
  let peticionesDatos = 0;
  const { dom } = montarPagina({
    validateImpl: respuesta(500, {}),
    fetchImpl: async () => {
      peticionesDatos++;
      return respuesta(200, { alerts: [alerta()] });
    },
  });
  await cargarSiemAlert();

  assert.equal(peticionesDatos, 0);
  assert.equal(filasTabla(dom).length, 0);
});

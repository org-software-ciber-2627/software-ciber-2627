import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (archivo) =>
  JSON.parse(
    readFileSync(
      new URL(`../../04-escaner/contract/dashboard/${archivo}`, import.meta.url),
      "utf8"
    )
  );

const catalogo = leer("catalogo.json");
const hallazgos = leer("informe_con_hallazgos.json");
const vacio = leer("informe_vacio.json");
const pendiente = leer("pendiente.json");
const enCurso = leer("en_curso.json");

const error404 = leer("error_404.json");
const error500Escaneo = leer("error_500_escaneo.json");
const error500Interno = leer("error_500_interno.json");

const SEVERIDADES = ["low", "medium", "high", "critical"];
const PERFILES = ["quick", "web", "vuln"];
const ESTADOS = ["pending", "running", "completed", "failed"];

test("el catálogo contiene escaneos con los campos y valores del contrato", () => {
  assert.ok(Array.isArray(catalogo));

  for (const scan of catalogo) {
    for (const campo of ["scan_id", "created_at", "target", "profile", "status"]) {
      assert.ok(Object.hasOwn(scan, campo), `Falta "${campo}"`);
    }

    assert.equal(typeof scan.scan_id, "string");
    assert.equal(typeof scan.target, "string");
    assert.ok(PERFILES.includes(scan.profile));
    assert.ok(ESTADOS.includes(scan.status));

    if (scan.created_at !== null) {
      assert.ok(/^\d{4}-\d{2}-\d{2}T.*Z$/.test(scan.created_at));
      assert.ok(!Number.isNaN(Date.parse(scan.created_at)));
    }
  }

  for (let i = 1; i < catalogo.length; i++) {
    assert.ok(
      Date.parse(catalogo[i - 1].created_at) >=
      Date.parse(catalogo[i].created_at),
      "El catálogo debe estar ordenado del más reciente al más antiguo"
    );
  }
});

test("el informe contiene hallazgos con la estructura del contrato", () => {
  assert.ok(Array.isArray(hallazgos));
  assert.ok(hallazgos.length > 0);

  for (const h of hallazgos) {
    for (const campo of [
      "event_id", "timestamp", "source", "event_type",
      "severity", "title", "description", "details"
    ]) {
      assert.ok(Object.hasOwn(h, campo), `Falta "${campo}"`);
    }

    assert.equal(h.source, "scanner");
    assert.equal(h.event_type, "vulnerability_detected");
    assert.ok(SEVERIDADES.includes(h.severity));
    assert.ok(/^\d{4}-\d{2}-\d{2}T.*Z$/.test(h.timestamp));
    assert.ok(!Number.isNaN(Date.parse(h.timestamp)));

    const d = h.details;
    assert.equal(typeof d.target.ip, "string");
    assert.ok(Number.isInteger(d.target.port) || d.target.port === null);
    assert.ok(d.target.protocol === null || typeof d.target.protocol === "string");
    assert.ok(d.target.service === null || typeof d.target.service === "string");

    for (const campo of ["scan_id", "tool", "profile"]) {
      assert.equal(typeof d[campo], "string");
    }

    for (const campo of ["script_id", "evidence", "cve"]) {
      assert.ok(d[campo] === null || typeof d[campo] === "string");
    }

    assert.ok(
      d.cvss === null ||
      (typeof d.cvss === "number" && d.cvss >= 0 && d.cvss <= 10)
    );
  }
});

test("un informe sin vulnerabilidades devuelve una lista vacía", () => {
  assert.ok(Array.isArray(vacio));
  assert.equal(vacio.length, 0);
});

test("los estados pendientes y los errores respetan el formato del contrato", () => {
  for (const respuesta of [pendiente, enCurso]) {
    assert.equal(typeof respuesta.scan_id, "string");
    assert.ok(["pendiente", "en_curso"].includes(respuesta.estado));
    assert.equal(typeof respuesta.mensaje, "string");
  }

  assert.equal(pendiente.estado, "pendiente");
  assert.equal(enCurso.estado, "en_curso");

  for (const respuesta of [error404, error500Escaneo, error500Interno]) {
    assert.equal(typeof respuesta.error.codigo, "string");
    assert.equal(typeof respuesta.error.mensaje, "string");
  }

  assert.equal(error404.error.codigo, "SCAN_NOT_FOUND");
  assert.equal(error500Escaneo.error.codigo, "SCAN_FAILED");
  assert.equal(error500Interno.error.codigo, "INTERNAL_ERROR");
});
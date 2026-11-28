// El mock mocks/siem-alerts.json debe seguir la forma del contrato de consumo del SIEM
// (contract/README.md), porque el Dashboard se desarrolla contra él.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (ruta) => JSON.parse(readFileSync(new URL(ruta, import.meta.url), "utf8"));

const mock = leer("../mocks/siem-alerts.json");

const SEVERIDADES = ["critical", "high", "medium", "low"];

test("el mock tiene la forma { alerts: [...] } con al menos una alerta", () => {
  assert.ok(Array.isArray(mock.alerts));
  assert.ok(mock.alerts.length > 0);
});

test("cada alerta trae los campos que pinta el Dashboard", () => {
  for (const a of mock.alerts) {
    for (const campo of ["alert_id", "timestamp", "source", "severity", "title"]) {
      assert.ok(a[campo], `${a.alert_id ?? "(sin id)"} no tiene "${campo}"`);
    }
  }
});

test("las severidades del mock son valores que el Dashboard sabe ordenar", () => {
  for (const a of mock.alerts) {
    assert.ok(SEVERIDADES.includes(a.severity), `${a.alert_id}: severidad "${a.severity}"`);
  }
});

test("las marcas de tiempo del mock son fechas válidas", () => {
  for (const a of mock.alerts) {
    assert.ok(!Number.isNaN(new Date(a.timestamp).getTime()), `${a.alert_id}: ${a.timestamp}`);
  }
});

test("los alert_id del mock no se repiten", () => {
  const ids = mock.alerts.map((a) => a.alert_id);
  assert.equal(new Set(ids).size, ids.length);
});

const FUENTES = ["ids", "honeypot", "scanner"];

test("cada alerta contiene todos los campos obligatorios del contrato SIEM", () => {
  for (const a of mock.alerts) {
    for (const campo of [
      "alert_id",
      "event_id",
      "timestamp",
      "source",
      "event_type",
      "severity",
      "title",
      "description",
      "source_ip",
      "target_ip",
      "details",
    ]) {
      assert.ok(
        Object.hasOwn(a, campo),
        `${a.alert_id}: falta el campo "${campo}"`
      );
    }
  }
});

test("el origen de cada alerta pertenece al enum del contrato", () => {
  for (const a of mock.alerts) {
    assert.ok(
      FUENTES.includes(a.source),
      `${a.alert_id}: origen no válido "${a.source}"`
    );
  }
});

test("cada alerta tiene un objeto details", () => {
  for (const a of mock.alerts) {
    assert.equal(
      typeof a.details,
      "object",
      `${a.alert_id}: details debe ser un objeto`
    );
    assert.ok(a.details !== null);
    assert.ok(!Array.isArray(a.details));
  }
});

test("las direcciones IP pueden ser IPv4 o null", () => {
  const ipv4 =
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  for (const a of mock.alerts) {
    for (const campo of ["source_ip", "target_ip"]) {
      assert.ok(
        a[campo] === null ||
          (typeof a[campo] === "string" && ipv4.test(a[campo])),
        `${a.alert_id}: ${campo} no es una IPv4 válida ni null`
      );
    }
  }
});
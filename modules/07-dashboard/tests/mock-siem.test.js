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

import { test } from "node:test";
import assert from "node:assert/strict";
import { filtrarAlertas } from "../src/SIEM-filtros.js";

const alertas = [
    { alert_id: "1", severity: "critical", source: "ids", timestamp: "2026-09-22T10:00:00.000Z" },
    { alert_id: "2", severity: "high", source: "scanner", timestamp: "2026-09-23T12:00:00.000Z" },
    { alert_id: "3", severity: "medium", source: "ids", timestamp: "2026-09-24T15:00:00.000Z" },
    { alert_id: "4", severity: "low", source: "honeypot", timestamp: "2026-09-25T18:00:00.000Z" },
    { alert_id: "5", severity: "high", source: "ids", timestamp: "2026-09-23T23:59:59.999Z" },
    { alert_id: "6", severity: "high", source: "scanner", timestamp: "2026-09-24T00:00:00.000Z" },
];

const ids = resultado => resultado.map(alerta => alerta.alert_id).sort();
const sinFiltros = { severidad: "", origen: "", desde: "", hasta: "" };

test("filtra por severidad", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, { ...sinFiltros, severidad: "critical" })),
        ["1"]
    );
});

test("filtra por origen", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, { ...sinFiltros, origen: "ids" })),
        ["1", "3", "5"]
    );
});

test("incluye alertas desde el inicio de la fecha UTC indicada", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, { ...sinFiltros, desde: "2026-09-24" })),
        ["3", "4", "6"]
    );
});

test("incluye todo el día hasta y excluye la medianoche siguiente", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, { ...sinFiltros, hasta: "2026-09-23" })),
        ["1", "2", "5"]
    );
});

test("combina severidad y origen", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, {
            ...sinFiltros,
            severidad: "medium",
            origen: "ids",
        })),
        ["3"]
    );
});

test("combina todos los filtros con lógica AND", () => {
    assert.deepEqual(
        ids(filtrarAlertas(alertas, {
            severidad: "medium",
            origen: "ids",
            desde: "2026-09-24",
            hasta: "2026-09-24",
        })),
        ["3"]
    );
});

test("sin filtros devuelve todas las alertas", () => {
    assert.deepEqual(ids(filtrarAlertas(alertas, sinFiltros)), ["1", "2", "3", "4", "5", "6"]);
});
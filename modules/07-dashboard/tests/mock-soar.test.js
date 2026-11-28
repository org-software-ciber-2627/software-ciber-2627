import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const incidentes = JSON.parse(
  readFileSync(new URL("../mocks/soar-incidents.json", import.meta.url), "utf8")
);

const SEVERIDADES = ["low", "medium", "high", "critical"];
const ESTADOS = ["open", "in_progress", "contained", "closed"];

test("los incidentes contienen los campos obligatorios del contrato SOAR", () => {
  assert.ok(Array.isArray(incidentes));
  assert.ok(incidentes.length > 0);

  for (const inc of incidentes) {
    for (const campo of [
      "id", "alert_key", "alert", "first_seen",
      "incident_id", "alert_id", "event_type",
      "severity", "priority", "source_ip", "status",
      "created_at", "resolved_at", "applied_playbook",
      "automation", "responses"
    ]) {
      assert.ok(
        Object.hasOwn(inc, campo),
        `${inc.incident_id}: falta el campo "${campo}"`
      );
    }

    assert.equal(typeof inc.id, "number");
    assert.equal(typeof inc.alert_key, "string");
    assert.equal(typeof inc.alert, "object");
    assert.ok(inc.alert !== null);
    assert.ok(Array.isArray(inc.responses));
  }
});

test("los valores de severidad, prioridad y estado respetan los enums", () => {
  for (const inc of incidentes) {
    assert.ok(SEVERIDADES.includes(inc.severity));
    assert.ok(SEVERIDADES.includes(inc.priority));
    assert.ok(ESTADOS.includes(inc.status));
  }
});

test("la automatización y las respuestas respetan sus contratos", () => {
  for (const inc of incidentes) {
    assert.equal(typeof inc.automation.automatable, "boolean");
    assert.ok(
      inc.automation.playbook === null ||
      typeof inc.automation.playbook === "string"
    );
    assert.equal(typeof inc.automation.reason, "string");

    for (const r of inc.responses) {
      for (const campo of [
        "response_id", "incident_id", "playbook",
        "action", "executed_at"
      ]) {
        assert.ok(
          Object.hasOwn(r, campo),
          `${inc.incident_id}: respuesta sin "${campo}"`
        );
      }

      assert.ok(
        ["pending", "running", "success", "failed", "skipped"].includes(r.status)
      );
      assert.ok(["automatic", "manual"].includes(r.triggered_by));
      assert.ok(!Number.isNaN(Date.parse(r.executed_at)));
    }
  }
});
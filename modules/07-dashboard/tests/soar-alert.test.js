
import { test } from "node:test";
import assert from "node:assert/strict";
import { respuesta, montarPagina } from "./helpers.js";

const SRC = new URL("../src/", import.meta.url);
let contador = 0;

function incidente(extra = {}) {
    return {
        incident_id: "SOAR-TEST-1",
        alert_id: "SIEM-TEST-1",
        severity: "high",
        status: "open",
        applied_playbook: "aislar-host",
        ...extra
    };
}

async function cargarSoarAlert(dom) {
    const url = new URL("SOAR-alert.js", SRC);
    url.searchParams.set("prueba", String(++contador));

    await import(url.href);

    // SOAR se inicializa al recibir DOMContentLoaded.
    dom.window.document.dispatchEvent(
        new dom.window.Event("DOMContentLoaded")
    );

    for (let i = 0; i < 10; i++) {
        await new Promise((r) => setImmediate(r));
    }
}

const visible = (dom, id) =>
    dom.window.document.getElementById(id).style.display !== "none";

test("SOAR muestra los incidentes y oculta el aviso cuando la consulta funciona", async () => {
    const { dom } = montarPagina({
        fetchImpl: async (url) => {
            if (String(url).includes("/api/soar/incidents")) {
                return respuesta(200, [incidente()]);
            }

            if (String(url).includes("/api/soar/metrics")) {
                return respuesta(200, {
                    mttd: 10,
                    mttr: 20,
                    period: "Periodo de prueba"
                });
            }

            return respuesta(200, { alerts: [] });
        }
    });

    await cargarSoarAlert(dom);

    const filas = dom.window.document.querySelectorAll("#soar-body tr");

    assert.equal(filas.length, 1);
    assert.match(filas[0].textContent, /SOAR-TEST-1/);
    assert.equal(visible(dom, "error-soar"), false);
});

test("SOAR conserva los incidentes cuando falla una actualización", async () => {
    let consultas = 0;

    const { dom, temporizadores } = montarPagina({
        fetchImpl: async (url) => {
            if (String(url).includes("/api/soar/incidents")) {
                consultas++;

                if (consultas === 1) {
                    return respuesta(200, [incidente()]);
                }

                return respuesta(500, {});
            }

            if (String(url).includes("/api/soar/metrics")) {
                return respuesta(200, {
                    mttd: 10,
                    mttr: 20,
                    period: "Periodo de prueba"
                });
            }

            return respuesta(200, { alerts: [] });
        }
    });

    await cargarSoarAlert(dom);

    const filasAntes = dom.window.document.querySelectorAll("#soar-body tr");
    assert.equal(filasAntes.length, 1);

    // El primer intervalo pertenece a SIEM; el último, a SOAR.
    const intervaloSOAR = temporizadores.at(-1);

    assert.equal(intervaloSOAR.ms, 30000);

    intervaloSOAR.fn();

    for (let i = 0; i < 10; i++) {
        await new Promise((r) => setImmediate(r));
    }

    const filasDespues = dom.window.document.querySelectorAll("#soar-body tr");

    assert.equal(filasDespues.length, 1);
    assert.match(filasDespues[0].textContent, /SOAR-TEST-1/);
    assert.equal(visible(dom, "error-soar"), true);
});

test("SOAR muestra el aviso de antigüedad después de 60 segundos sin datos", async () => {
    const ahoraOriginal = Date.now;
    let ahoraFalsa = 1800000000000;
    Date.now = () => ahoraFalsa;

    try {
        const { dom, temporizadores } = montarPagina({
            fetchImpl: async (url) => {
                if (String(url).includes("/api/soar/incidents")) {
                    if (ahoraFalsa === 1800000000000) {
                        return respuesta(200, [incidente()]);
                    }

                    return respuesta(500, {});
                }

                if (String(url).includes("/api/soar/metrics")) {
                    return respuesta(200, {
                        mttd: 10,
                        mttr: 20,
                        period: "Periodo de prueba"
                    });
                }

                return respuesta(200, { alerts: [] });
            }
        });

        await cargarSoarAlert(dom);

        ahoraFalsa += 60001;
        temporizadores.at(-1).fn();

        for (let i = 0; i < 10; i++) {
            await new Promise((r) => setImmediate(r));
        }

        const aviso = dom.window.document.getElementById("error-soar");

        assert.equal(visible(dom, "error-soar"), true);
        assert.match(aviso.textContent, /^Sin datos desde \d{2}:\d{2}$/);
        assert.equal(
            dom.window.document.querySelectorAll("#soar-body tr").length,
            1
        );
    } finally {
        Date.now = ahoraOriginal;
    }
});

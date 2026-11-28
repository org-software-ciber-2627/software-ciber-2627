import { test } from "node:test";
import assert from "node:assert/strict";
import {
    crearSeguimiento,
    UMBRAL_ANTIGUEDAD
} from "../src/api-estado.js";

test("el umbral de antigüedad es de 60 segundos", () => {
    assert.equal(UMBRAL_ANTIGUEDAD, 60000);
});

test("sin una consulta correcta previa no muestra aviso de antigüedad", () => {
    const seguimiento = crearSeguimiento();

    assert.equal(seguimiento.obtenerAviso(100000), null);
    assert.equal(seguimiento.tieneDatos(), false);
});

test("no muestra aviso antes de superar los 60 segundos", () => {
    const seguimiento = crearSeguimiento();

    seguimiento.registrarExito(100000);

    assert.equal(seguimiento.obtenerAviso(159999), null);
});

test("muestra el aviso al alcanzar los 60 segundos", () => {
    const seguimiento = crearSeguimiento();

    seguimiento.registrarExito(100000);

    assert.match(
        seguimiento.obtenerAviso(160000),
        /^Sin datos desde \d{2}:\d{2}$/
    );
});

test("una consulta correcta reinicia el seguimiento", () => {
    const seguimiento = crearSeguimiento();

    seguimiento.registrarExito(100000);
    seguimiento.registrarExito(200000);

    assert.equal(seguimiento.obtenerAviso(259999), null);
    assert.match(seguimiento.obtenerAviso(260000), /^Sin datos desde/);
});
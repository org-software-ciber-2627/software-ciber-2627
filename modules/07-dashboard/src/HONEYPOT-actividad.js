import { getHoneypotActivity } from "./HONEYPOT-client.js";
import { pintar as mostrarEstado } from "./api-estado.js";

const TIEMPO_REFRESCO = 30000;

// event_type del contrato del honeypot (modules/03-honeypot/contract/README.md).
const TIPOS = {
    intento_login: "Intento de acceso",
    fuerza_bruta: "Fuerza bruta",
    credenciales_por_defecto: "Credenciales por defecto",
    escaneo: "Escaneo"
};

// Los campos los controla el atacante (IP, servicio, tipo...), así que se escriben siempre con
// textContent y nunca con innerHTML. Tampoco se muestran usuario, contraseña ni comando.
function celda(texto) {
    const td = document.createElement("td");
    td.textContent = texto;
    return td;
}

function formatearHora(marca) {
    const fecha = new Date(marca);
    return Number.isNaN(fecha.getTime()) ? String(marca ?? "—") : fecha.toLocaleString();
}

export function pintarActividad(eventos) {
    const tbody = document.getElementById("honeypot-body");
    if (!tbody) return;

    tbody.textContent = "";

    for (const e of eventos) {
        const d = e.details ?? {};
        const tipo = Object.hasOwn(TIPOS, e.event_type) ? TIPOS[e.event_type] : (e.event_type ?? "—");

        const tr = document.createElement("tr");
        tr.append(
            celda(formatearHora(e.timestamp)),
            celda(d.source_ip ?? "—"),
            celda(d.service ?? "—"),
            celda(tipo)
        );
        tbody.appendChild(tr);
    }
}

export async function cargarHoneypot() {
    const resultado = await getHoneypotActivity();
    mostrarEstado(document.getElementById("error-honeypot"), resultado, pintarActividad);
}

cargarHoneypot();
setInterval(cargarHoneypot, TIEMPO_REFRESCO);

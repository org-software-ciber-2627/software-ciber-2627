import { pedirLista } from "./api-estado.js";

// Historial de eventos del SIEM (GET /events, contract/history-events.md del SIEM). Va por el mismo
// proxy de nginx que las alertas. El SIEM no filtra por origen: se pide la última página (500 eventos
// como máximo, de más reciente a más antiguo) y aquí se queda solo lo que viene del honeypot.
const EVENTOS_URL = "/api/siem/events?limit=500&offset=0";
export const MAX_EVENTOS = 20;

const marca = (e) => Date.parse(e.timestamp) || 0;

// Respuesta del SIEM -> eventos del honeypot, el más reciente primero. Devuelve null si la
// respuesta no tiene la forma { events: [...] }, para que pedirLista la trate como inesperada.
export function actividadHoneypot(respuesta) {
    const lista = Array.isArray(respuesta) ? respuesta : respuesta?.events;
    if (!Array.isArray(lista)) return null;

    return lista
        .filter((e) => e && e.source === "honeypot")
        .sort((a, b) => marca(b) - marca(a))
        .slice(0, MAX_EVENTOS);
}

// Como getAlerts(): no lanza errores, devuelve { estado, datos, mensaje } (ver api-estado.js).
export function getHoneypotActivity() {
    return pedirLista(EVENTOS_URL, actividadHoneypot, "el SIEM");
}

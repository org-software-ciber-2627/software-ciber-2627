import { pedirLista } from "./api-estado.js";
const SIEM_URL = "/api/siem/alerts"; //proxy de nginx hacia el SIEM real (ver default.conf). Mock: "../mocks/siem-alerts.json"

// El 401 del listado lo gestiona api-estado.js (pedirLista); este redireccionamiento lo usa el detalle.
function redirigirAlLogin() {
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("logged_in");
    window.location.replace("login.html");
}

export function getAlerts() {
    return pedirLista(SIEM_URL, (d) => Array.isArray(d) ? d : d.alerts, "el SIEM");
}

export async function getAlertById(id) {
    const token = sessionStorage.getItem("token") || "token-de-prueba";

    const r = await fetch(`${SIEM_URL}/${encodeURIComponent(id)}`, {
        headers: { "Authorization": "Bearer " + token }
    });

    if (r.status === 401) {
        redirigirAlLogin();
        throw new Error("Sesión caducada o rechazada");
    }
    if (r.status === 403) {
        throw new Error("Sin permiso");
    }

    if (r.status === 404) {
        throw new Error("ALERT_NOT_FOUND");
    }

    if (!r.ok) {
        throw new Error(`Error ${r.status}`);
    }

    return await r.json();
}

const SIEM_URL = "/api/siem/alerts"; //proxy de nginx hacia el SIEM real (ver default.conf). Mock: "../mocks/siem-alerts.json"

export async function getAlerts() {
    const token = sessionStorage.getItem("token") || "token-de-prueba"; //de prueba (se implementa cuando se junte con el grupo 1)
    const r = await fetch(SIEM_URL, {
        headers: { "Authorization": "Bearer " + token }
    });
    if (r.status === 401 || r.status === 403) throw new Error("Sin permiso");
    if (!r.ok) throw new Error(r.status);
    const data = await r.json();
    return data.alerts;
}

export async function getAlertById(id) {
    const token = sessionStorage.getItem("token") || "token-de-prueba";

    const r = await fetch(`${SIEM_URL}/${encodeURIComponent(id)}`, {
        headers: { "Authorization": "Bearer " + token }
    });

    if (r.status === 401 || r.status === 403) {
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

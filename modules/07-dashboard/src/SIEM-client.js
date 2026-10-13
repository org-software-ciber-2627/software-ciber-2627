const SIEM_URL = "../mocks/siem-alerts.json"; //SIEM real: "http://localhost:8005/alerts

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
const SIEM_URL = "../mocks/alerts-SIEM.json";

export async function getAlerts() {
    const token = sessionStorage.getItem("token") || "token-de-prueba"; //de prueba porq  todavia no existe el login
    const r = await fetch(SIEM_URL, {
        headers: { "Authorization": "Bearer " + token }
    });
    if (r.status === 401 || r.status === 403) throw new Error("Sin permiso");
    if (!r.ok) throw new Error(r.status);
    const data = await r.json();
    return data.alerts;
}
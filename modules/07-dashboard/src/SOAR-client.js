const SOAR_URL = "./mocks/soar-incidents.json";

export async function getSOARIncidents() {
    const token = sessionStorage.getItem("token") || "token-de-prueba";
    
    const r = await fetch(SOAR_URL, {
        headers: { "Authorization": "Bearer " + token }
    });

    if (r.status === 401 || r.status === 403) {
        throw new Error("Sin permiso");
    }

    if (!r.ok) {
        throw new Error(`Error ${r.status}`);
    }
    
    // Devuelve directamente la lista de incidentes (según el contrato del SOAR)
    return await r.json(); 
}
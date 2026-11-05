// Pide una lista a un servicio externo y siempre devuelve { estado, datos, mensaje }.
// estado: "ok" | "vacio" | "error" | "sin_permiso" | "pendiente"
export async function pedirLista(url, extraer = (d) => d, nombre = "el servicio") {
    const token = sessionStorage.getItem("token") || "token-de-prueba";
    let r;
    try {
        r = await fetch(url, { headers: { "Authorization": "Bearer " + token } });
    } catch {
        return { estado: "error", datos: [], mensaje: `No se pudo conectar con ${nombre}.` };
    }

    if (r.status === 401) { 
        sessionStorage.removeItem("token");
        sessionStorage.removeItem("logged_in");
        window.location.href = "login.html";
        return { estado: "sin_permiso", datos: [], mensaje: "Sesión caducada. Vuelve a iniciar sesión." };
    }
    if (r.status === 403) return { estado: "sin_permiso", datos: [], mensaje: `No tienes permiso para consultar ${nombre}.` };
    if (r.status === 202) return { estado: "pendiente", datos: [], mensaje: "Los datos aún no están disponibles." };
    if (!r.ok) return { estado: "error", datos: [], mensaje: `Error al consultar ${nombre} (código ${r.status}).` };

    let datos;
    try { datos = extraer(await r.json()); } catch { datos = null; }
    if (!Array.isArray(datos)) return { estado: "error", datos: [], mensaje: `Respuesta inesperada de ${nombre}.` };

    return datos.length === 0
        ? { estado: "vacio", datos, mensaje: "Sin datos." }
        : { estado: "ok", datos, mensaje: "" };
}

export function pintar(aviso, resultado, pintarLista) {
    if (resultado.estado === "ok") {
        aviso.style.display = "none";
        return pintarLista(resultado.datos);
    }
    pintarLista([]); 
    aviso.textContent = resultado.mensaje;
    aviso.className = resultado.estado === "vacio" ? "aviso-vacio" : "aviso-error";
    aviso.style.display = "block";
}
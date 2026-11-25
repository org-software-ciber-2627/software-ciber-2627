import { pedirLista } from "./api-estado.js";

const ESCANER_URL = "/api/escaner/scans"; // proxy de nginx hacia el Escáner real (ver default.conf)

function elegirUltimo(escaneos) {
    return escaneos
        .filter(s => s.status === "completed")
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
}

export async function getHallazgosUltimoEscaneo() {
    const lista = await pedirLista(
        ESCANER_URL,
        (d) => Array.isArray(d) ? d : d.scans,
        "el Escáner"
    );
    if (lista.estado === "vacio") return { ...lista, mensaje: "No hay escaneos todavía." };
    if (lista.estado !== "ok") return lista;

    const ultimo = elegirUltimo(lista.datos);
    if (!ultimo) return { estado: "vacio", datos: [], mensaje: "Aún no hay ningún escaneo terminado." };

    const informe = await pedirLista(
        `${ESCANER_URL}/${encodeURIComponent(ultimo.scan_id)}/report`,
        (d) => d,
        "el Escáner"
    );
    return { ...informe, scan_id: ultimo.scan_id };
}
import { pedirLista } from "./api-estado.js";

const SOAR_URL = "/api/soar";

export function getSOARIncidents() {
    return pedirLista(`${SOAR_URL}/incidents`, (d) => d, "el SOAR");
}

function calcularMetricasRespaldo(incidents) {
    if (!Array.isArray(incidents) || incidents.length === 0) {
        return { mttd: null, mttr: null, period: "Sin incidentes registrados" };
    }

    let sumaMttd = 0, countMttd = 0;
    let sumaMttr = 0, countMttr = 0;
    let minFecha = Infinity, maxFecha = -Infinity;

    for (const inc of incidents) {
        const creado = inc.created_at ? new Date(inc.created_at).getTime() : NaN;
        const alertaTs = inc.alert?.timestamp ? new Date(inc.alert.timestamp).getTime() : NaN;
        const resuelto = inc.resolved_at ? new Date(inc.resolved_at).getTime() : NaN;

        if (!Number.isNaN(creado)) {
            if (creado < minFecha) minFecha = creado;
            if (creado > maxFecha) maxFecha = creado;
        }

        if (!Number.isNaN(creado) && !Number.isNaN(alertaTs) && creado >= alertaTs) {
            sumaMttd += (creado - alertaTs) / 1000;
            countMttd++;
        }

        if (!Number.isNaN(resuelto) && !Number.isNaN(creado) && resuelto >= creado) {
            sumaMttr += (resuelto - creado) / 1000;
            countMttr++;
        }
    }

    const period = Number.isFinite(minFecha)
        ? `${new Date(minFecha).toLocaleDateString()} - ${new Date(maxFecha).toLocaleDateString()}`
        : "Histórico disponible";

    return {
        mttd: countMttd > 0 ? Math.round(sumaMttd / countMttd) : null,
        mttr: countMttr > 0 ? Math.round(sumaMttr / countMttr) : null,
        period
    };
}

export async function getSOARMetrics(incidentsFallback = []) {
    try {
        const token = sessionStorage.getItem("token");
        const headers = token ? { Authorization: `Bearer ${token}` } : {};
        const res = await fetch(`${SOAR_URL}/metrics`, { headers });

        if (res.ok) {
            const data = await res.json();
            return {
                mttd: data.mttd ?? data.mttd_seconds ?? null,
                mttr: data.mttr ?? data.mttr_seconds ?? null,
                period: data.period ?? data.periodo ?? data.window ?? "Periodo actual SOAR"
            };
        }
    } catch {
        // Respaldo activo mientras G6 despliega GET /metrics esta semana
    }

    return calcularMetricasRespaldo(incidentsFallback);
}
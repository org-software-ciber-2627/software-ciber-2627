import { getSOARIncidents, getSOARMetrics } from './SOAR-client.js';
import { pintar as mostrarEstado } from './api-estado.js';
import { abrirDetalle } from './SIEM-alert.js';

function esc(t) {
    const d = document.createElement('div');
    d.textContent = t ?? '';
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatearDuracion(segundos) {
    if (segundos === null || segundos === undefined || Number.isNaN(Number(segundos))) {
        return 'N/D';
    }
    const seg = Math.round(Number(segundos));
    if (seg < 60) return `${seg} s`;
    const min = Math.floor(seg / 60);
    const restoSeg = seg % 60;
    if (min < 60) return restoSeg > 0 ? `${min} min ${restoSeg} s` : `${min} min`;
    const horas = Math.floor(min / 60);
    const restoMin = min % 60;
    return `${horas} h ${restoMin} min`;
}

function pintarMetricas(metricas) {
    const elMttd = document.getElementById('soar-mttd');
    const elMttr = document.getElementById('soar-mttr');
    const elPeriodo = document.getElementById('soar-periodo');

    if (elMttd) elMttd.textContent = formatearDuracion(metricas?.mttd);
    if (elMttr) elMttr.textContent = formatearDuracion(metricas?.mttr);
    if (elPeriodo) elPeriodo.textContent = metricas?.period || 'Sin datos';
}

function pintarIncidentes(incidents) {
    const tbody = document.getElementById('soar-body');
    if (!tbody) return;

    tbody.textContent = '';

    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        const celdaAlerta = inc.alert_id
            ? `<button type="button" class="ver-alerta-origen" data-alert-id="${esc(inc.alert_id)}">${esc(inc.alert_id)}</button>`
            : 'Sin alerta';

        tr.innerHTML = `
            <td>${esc(inc.incident_id)}</td>
            <td>${celdaAlerta}</td>
            <td><span class="sev ${esc(inc.severity || 'low')}">${esc(inc.status)}</span></td>
            <td>${inc.applied_playbook ? esc(inc.applied_playbook) : 'Ninguno'}</td>
        `;
        tbody.appendChild(tr);
    });
}

document.getElementById('soar-body')?.addEventListener('click', e => {
    const boton = e.target.closest('.ver-alerta-origen');
    if (boton && boton.dataset.alertId) {
        abrirDetalle(boton.dataset.alertId);
    }
});

async function initSOAR() {
    const resultado = await getSOARIncidents();
    mostrarEstado(document.getElementById('error-soar'), resultado, pintarIncidentes);

    const incidentes = resultado.estado === 'ok' ? resultado.datos : [];
    const metricas = await getSOARMetrics(incidentes);
    pintarMetricas(metricas);
}

document.addEventListener('DOMContentLoaded', initSOAR);
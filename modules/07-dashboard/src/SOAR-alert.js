import { getSOARIncidents } from './SOAR-client.js';
import { pintar as mostrarEstado } from './api-estado.js';

function esc(t) { 
    const d = document.createElement('div');
    d.textContent = t ?? '';
    // innerHTML no escapa las comillas y el valor se usa también dentro de class="..."
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function pintarIncidentes(incidents) { 
    const tbody = document.getElementById('soar-body');
    if (!tbody) return;

    tbody.textContent = '';

    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${esc(inc.incident_id)}</td>
            <td>${esc(inc.alert_id)}</td>
            <td><span class="sev ${esc(inc.severity || 'low')}">${esc(inc.status)}</span></td>
            <td>${inc.applied_playbook ? esc(inc.applied_playbook) : 'Ninguno'}</td>
        `; 
        tbody.appendChild(tr);
    });
}

async function initSOAR() {
    const resultado = await getSOARIncidents(); 
    mostrarEstado(document.getElementById('error-soar'), resultado, pintarIncidentes); 
}

document.addEventListener('DOMContentLoaded', initSOAR);
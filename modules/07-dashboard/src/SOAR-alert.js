import { getSOARIncidents } from './SOAR-client.js';

async function initSOAR() {
    try {
        const incidents = await getSOARIncidents();
        const tbody = document.getElementById('soar-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (!incidents || incidents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No hay incidentes registrados.</td></tr>';
            return;
        }

        incidents.forEach(inc => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${inc.incident_id}</td>
                <td>${inc.alert_id}</td>
                <td><span class="sev ${inc.severity || 'low'}">${inc.status}</span></td>
                <td>${inc.applied_playbook ? inc.applied_playbook : 'Ninguno'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        console.error("Error al cargar incidentes SOAR:", error);
        const errDiv = document.getElementById('error-soar');
        if (errDiv) errDiv.style.display = 'block';
    }
}

document.addEventListener('DOMContentLoaded', initSOAR);
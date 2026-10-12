document.addEventListener('DOMContentLoaded', () => {
    // Para el Sprint 1, consumimos el mock localmente. 
    // En sprints futuros, esto apuntará a la API real del SIEM.
    fetch('../mocks/siem-alerts.json')
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('alerts-body');
            data.forEach(alert => {
                const tr = document.createElement('tr');
                const severityClass = alert.severidad === 'ALTA' ? 'high' : '';
                tr.innerHTML = `
                    <td>${alert.id}</td>
                    <td>${alert.fecha}</td>
                    <td class="${severityClass}">${alert.severidad}</td>
                    <td>${alert.descripcion}</td>
                    <td>${alert.origen_ip}</td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(error => console.error('Error cargando los mocks:', error));
});
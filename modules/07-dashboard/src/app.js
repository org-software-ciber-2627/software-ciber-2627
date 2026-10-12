document.addEventListener('DOMContentLoaded', () => {
    const TIEMPO_REFRESCO = 30000; // 30 segundos (configurable)

    function cargarDatos() {
        fetch('../mocks/siem-alerts.json')
            .then(response => response.json())
            .then(data => {
                const tbody = document.getElementById('alerts-body');
                tbody.innerHTML = ''; 
                
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

                const ahora = new Date();
                document.getElementById('hora-actualizacion').innerText = ahora.toLocaleTimeString();
            })
            .catch(error => console.error('Error cargando los mocks:', error));
    }


    cargarDatos();

    setInterval(cargarDatos, TIEMPO_REFRESCO);
});
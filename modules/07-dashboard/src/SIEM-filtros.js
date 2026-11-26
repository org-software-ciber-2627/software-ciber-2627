export function filtrarAlertas(alertas, filtros) {
    const { severidad, origen, desde, hasta } = filtros;

    const fechaDesde = desde 
        ? new Date (`${desde}T00:00:00`) : null;

    const fechaHasta = hasta 
        ? new Date(`${hasta}T23:59:59.999`) : null;

    return alertas.filter(alerta => {
        const coincideSeveridad = 
            !severidad || alerta.severity === severidad;

        const coincideOrigen = 
            !origen || alerta.source === origen;

        const fechaAlerta = new Date(alerta.timestamp);

        const coincideDesde = 
            !fechaDesde || fechaAlerta >= fechaDesde;

        const coincideHasta =   
            !fechaHasta || fechaAlerta <= fechaHasta;

        return coincideSeveridad && 
            coincideOrigen && 
            coincideDesde && 
            coincideHasta;
    });
}
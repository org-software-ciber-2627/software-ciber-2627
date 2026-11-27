export function filtrarAlertas(alertas, filtros) {
    const { severidad, origen, desde, hasta } = filtros;

    const inicioDesde = desde
        ? Date.parse(`${desde}T00:00:00.000Z`)
        : null;

    const finHastaExclusivo = hasta
        ? Date.parse(`${hasta}T00:00:00.000Z`) + 86_400_000
        : null;

    return alertas.filter(alerta => {
        const coincideSeveridad =
            !severidad || alerta.severity === severidad;

        const coincideOrigen =
            !origen || alerta.source === origen;

        const fechaAlerta = Date.parse(alerta.timestamp);

        const coincideDesde =
            inicioDesde === null || fechaAlerta >= inicioDesde;

        const coincideHasta =
            finHastaExclusivo === null || fechaAlerta < finHastaExclusivo;

        return coincideSeveridad &&
            coincideOrigen &&
            coincideDesde &&
            coincideHasta;
    });
}
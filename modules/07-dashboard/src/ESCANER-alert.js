import { getHallazgosUltimoEscaneo } from "./ESCANER-client.js";
import { pintar as mostrarEstado } from "./api-estado.js";

const PESO = { critical: 4, high: 3, medium: 2, low: 1 };
const TIEMPO_REFRESCO = 30000;

function esc(t) {
  const d = document.createElement("div");
  d.textContent = t ?? "";
  return d.innerHTML;
}

function ordenar(hallazgos) {
  return [...hallazgos].sort((a, b) =>
    (PESO[b.severity] || 0) - (PESO[a.severity] || 0)
  );
}

function pintar(hallazgos) {
  document.getElementById("hallazgos-body").innerHTML =
    ordenar(hallazgos).map(h => {
      const t = h.details?.target ?? {};
      const clase = PESO[h.severity] ? h.severity : "";
      return `<tr>
        <td>${esc(t.ip)}</td>
        <td>${esc(t.port)}</td>
        <td>${esc(t.service)}</td>
        <td>${esc(h.title)}</td>
        <td><span class="sev ${clase}">${esc(h.severity)}</span></td>
      </tr>`;
    }).join("");
}

async function cargar() {
  const resultado = await getHallazgosUltimoEscaneo();
  mostrarEstado(document.getElementById("error-escaner"), resultado, pintar);
  document.getElementById("escaneo-id").textContent = resultado.scan_id ?? "-";
}

cargar();
setInterval(cargar, TIEMPO_REFRESCO);
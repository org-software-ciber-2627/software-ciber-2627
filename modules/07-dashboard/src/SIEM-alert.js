import { getAlerts } from "./SIEM-client.js";

const PESO = { critical: 4, high: 3, medium: 2, low: 1 };

function esc(t) {
  const d = document.createElement("div");
  d.textContent = t ?? "";
  return d.innerHTML;
}

function ordenar(alertas) {
  return [...alertas].sort((a, b) =>
    (PESO[b.severity] || 0) - (PESO[a.severity] || 0) ||
    new Date(b.timestamp) - new Date(a.timestamp)
  );
}

function pintar(alertas) {
  document.querySelector("#tabla tbody").innerHTML = ordenar(alertas).map(a => {
    const clase = PESO[a.severity] ? a.severity : "";
    return `<tr>
      <td><span class="sev ${clase}">${esc(a.severity)}</span></td>
      <td>${esc(a.title)}</td>
      <td>${esc(a.source)}</td>
      <td>${new Date(a.timestamp).toLocaleString()}</td>
    </tr>`;
  }).join("");
}

async function cargar() {
  try {
    pintar(await getAlerts());
  } catch (e) {
    document.getElementById("tabla").style.display = "none";
    document.getElementById("error").style.display = "block";
  }
}
cargar();
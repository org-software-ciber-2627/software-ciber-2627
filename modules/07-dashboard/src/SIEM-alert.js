import { getAlerts, getAlertById } from "./SIEM-client.js";

const PESO = { critical: 4, high: 3, medium: 2, low: 1 };
const TIEMPO_REFRESCO = 30000;

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
  document.querySelector("#tabla tbody").innerHTML =
    ordenar(alertas).map(a => {
      const clase = PESO[a.severity] ? a.severity : "";

      return `<tr>
        <td><span class="sev ${clase}">${esc(a.severity)}</span></td>
        <td>${esc(a.title)}</td>
        <td>${esc(a.source)}</td>
        <td>${esc(new Date(a.timestamp).toLocaleString())}</td>
        <td>
          <button type="button" class="ver-detalle"
            data-alert-id="${esc(a.alert_id)}">
            Ver detalle
          </button>
        </td>
      </tr>`;
    }).join("");
}

function mostrarDetalle(alerta) {
  const contenido = document.getElementById("contenido-detalle");

  const campos = [
    ["ID de alerta", alerta.alert_id],
    ["ID del evento", alerta.event_id],
    ["Fecha y hora", alerta.timestamp],
    ["Origen", alerta.source],
    ["Tipo de evento", alerta.event_type],
    ["Severidad", alerta.severity],
    ["Título", alerta.title],
    ["Descripción", alerta.description],
    ["IP de origen", alerta.source_ip],
    ["IP de destino", alerta.target_ip]
  ];

  contenido.innerHTML = campos.map(([nombre, valor]) =>
    `<p><strong>${esc(nombre)}:</strong> ${esc(valor)}</p>`
  ).join("") +
    `<p><strong>Detalles adicionales:</strong></p>
     <pre>${esc(JSON.stringify(alerta.details ?? {}, null, 2))}</pre>`;

  document.getElementById("tabla").style.display = "none";
  document.getElementById("hora-actualizacion").parentElement.parentElement.style.display = "none";
  document.getElementById("detalle-alerta").style.display = "block";
  document.getElementById("error").style.display = "none";
}

async function abrirDetalle(id) {
  try {
    const alerta = await getAlertById(id);
    mostrarDetalle(alerta);
  } catch (e) {
    const error = document.getElementById("error");
    error.textContent =
      e.message === "Sin permiso"
        ? "No tienes permiso para consultar esta alerta."
        : e.message === "ALERT_NOT_FOUND"
          ? "Alerta no encontrada."
          : "No se pudo cargar el detalle de la alerta.";
    error.style.display = "block";
  }
}

document.querySelector("#tabla tbody").addEventListener("click", e => {
  const boton = e.target.closest(".ver-detalle");
  if (boton) abrirDetalle(boton.dataset.alertId);
});

document.getElementById("volver-alertas").addEventListener("click", () => {
  document.getElementById("detalle-alerta").style.display = "none";
  document.getElementById("tabla").style.display = "";
  document.getElementById("hora-actualizacion").parentElement.parentElement.style.display = "";
  document.getElementById("error").style.display = "none";
  cargar();
});

async function cargar() {
  if (document.getElementById("detalle-alerta").style.display === "block") {
    return;
  }

  try {
    pintar(await getAlerts());
    document.getElementById("error").style.display = "none";
    document.getElementById("tabla").style.display = "";
    document.getElementById("hora-actualizacion").textContent =
      new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById("tabla").style.display = "none";
    document.getElementById("error").textContent =
      e.message === "Sin permiso"
        ? "No tienes permiso para consultar las alertas."
        : "No se pudo conectar con el SIEM.";
    document.getElementById("error").style.display = "block";
  }
}

cargar();
setInterval(cargar, TIEMPO_REFRESCO);

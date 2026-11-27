import { getAlerts, getAlertById } from "./SIEM-client.js";
import { logout, validate } from "./auth-client.js";
import { crearSeguimiento } from "./api-estado.js";
import { filtrarAlertas } from "./SIEM-filtros.js";

const seguimientoSIEM = crearSeguimiento();
const botonLogout = document.getElementById("logout-btn");

botonLogout.addEventListener("click", async () => {
  botonLogout.disabled = true;

  try {
    await logout();
  } finally {
    window.location.replace("login.html");
  }
});

const PESO = { critical: 4, high: 3, medium: 2, low: 1 };
const TIEMPO_REFRESCO = 30000;

let todasAlertas = [];

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

function actualizarOrigenes(alertas) {
  const selector = document.getElementById("filtro-origen");
  if (!selector) return;

  const origenSeleccionado = selector.value;

  const origenes = [...new Set(
    alertas.map(a => a.source).filter(Boolean)
  )].sort();

  selector.innerHTML = '<option value="">Todos</option>';

  origenes.forEach(origen => {
    const opcion = document.createElement("option");
    opcion.value = origen;
    opcion.textContent = origen;
    selector.appendChild(opcion);
  });

  selector.value = origenSeleccionado;
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

function aplicarFiltros() {
  const filtros = {
    severidad: document.getElementById("filtro-severidad")?.value || "",
    origen: document.getElementById("filtro-origen")?.value || "",
    desde: document.getElementById("filtro-desde")?.value || "",
    hasta: document.getElementById("filtro-hasta")?.value || ""
  };

  const alertasFiltradas = filtrarAlertas(todasAlertas, filtros);
  pintar(alertasFiltradas);
}

document.getElementById("aplicar-filtros")?.addEventListener("click", aplicarFiltros);

document.getElementById("limpiar-filtros")?.addEventListener("click", () => {
  document.getElementById("filtro-severidad").value = "";
  document.getElementById("filtro-origen").value = "";
  document.getElementById("filtro-desde").value = "";
  document.getElementById("filtro-hasta").value = "";

  aplicarFiltros();
});

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

export async function abrirDetalle(id) {
  try {
    const alerta = await getAlertById(id);
    mostrarDetalle(alerta);
    document.getElementById("detalle-alerta")?.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    const error = document.getElementById("error");
    error.textContent =
      e.message === "Sin permiso"
        ? "No tienes permiso para consultar esta alerta."
        : e.message === "ALERT_NOT_FOUND"
          ? "Alerta no encontrada."
          : "No se pudo cargar el detalle de la alerta.";

    error.className = "aviso-error";
    error.style.display = "block";
    error.scrollIntoView({ behavior: "smooth" });
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
  const sesion = await validate();

  if (!sesion.valid) {
    if (sesion.status === 401) {
      sessionStorage.removeItem("token");
      sessionStorage.removeItem("logged_in");
    }

    window.location.replace("login.html");
    return;
  }

  if (document.getElementById("detalle-alerta").style.display === "block") {
    return;
  }

  try {
    const resultado = await getAlerts();
    const aviso = document.getElementById("error");
    const tabla = document.getElementById("tabla");

    if (resultado.estado === "ok" || resultado.estado === "vacio") {
      seguimientoSIEM.registrarExito();
      todasAlertas = resultado.datos;
      actualizarOrigenes(todasAlertas);
      aplicarFiltros();

      aviso.style.display = resultado.estado === "vacio" ? "block" : "none";
      aviso.textContent = resultado.mensaje;
      aviso.className = resultado.estado === "vacio" ? "aviso-vacio" : "";
      tabla.style.display = "";
      document.getElementById("hora-actualizacion").textContent =
        new Date().toLocaleTimeString();
    } else if (
      resultado.estado === "error" &&
      seguimientoSIEM.tieneDatos() &&
      todasAlertas.length > 0
    ) {
      aplicarFiltros();
      aviso.textContent =
        seguimientoSIEM.obtenerAviso() || resultado.mensaje;
      aviso.className = "aviso-error";
      aviso.style.display = "block";
      tabla.style.display = "";
    } else {
      todasAlertas = [];
      pintar([]);
      aviso.textContent = resultado.mensaje;
      aviso.className = "aviso-error";
      aviso.style.display = "block";
      tabla.style.display = "none";
    }
  } catch (e) {
    console.error("ERROR REAL AL CARGAR ALERTAS:", e);
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


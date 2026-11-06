// Utilidades compartidas por las pruebas del Dashboard.
// El front es JavaScript puro (módulos ES) servido por nginx, así que las pruebas
// simulan el navegador con jsdom y sustituyen fetch por una función controlada.
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SRC = new URL("../src/", import.meta.url);

/** Alerta mínima con la forma del contrato del SIEM; se sobrescribe lo que importe en cada prueba. */
export function alerta(extra = {}) {
  return {
    alert_id: "SIEM-ALERT-TEST",
    event_id: "EV-TEST",
    timestamp: "2026-09-22T18:30:15Z",
    source: "ids",
    event_type: "port_scan",
    severity: "medium",
    title: "Alerta de prueba",
    description: "",
    source_ip: null,
    target_ip: null,
    ...extra,
  };
}

/** Respuesta falsa de fetch. */
export function respuesta(status, cuerpo) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => cuerpo,
  };
}

/** Define (o sustituye) un global aunque Node ya traiga uno propio. */
export function definirGlobal(nombre, valor) {
  Object.defineProperty(globalThis, nombre, {
    value: valor,
    configurable: true,
    writable: true,
  });
}

/** sessionStorage mínimo en memoria. */
export function storageEnMemoria(inicial = {}) {
  const datos = new Map(Object.entries(inicial));
  return {
    getItem: (k) => (datos.has(k) ? datos.get(k) : null),
    setItem: (k, v) => void datos.set(k, String(v)),
    removeItem: (k) => void datos.delete(k),
    clear: () => datos.clear(),
  };
}

/**
 * Monta index.html (sin scripts) en jsdom y deja document/sessionStorage como globales,
 * para poder importar SIEM-alert.js tal cual. Devuelve los temporizadores registrados.
 */
export function montarPagina({ fetchImpl, token } = {}) {
  const html = readFileSync(fileURLToPath(new URL("index.html", SRC)), "utf8")
    .replace(/<script[\s\S]*?<\/script>/g, "");
  const dom = new JSDOM(html, { url: "http://localhost:8007/index.html" });

  const temporizadores = [];
  definirGlobal("document", dom.window.document);
  definirGlobal("window", dom.window);
  definirGlobal(
    "sessionStorage",
    storageEnMemoria(token ? { token } : {})
  );
  definirGlobal("fetch", fetchImpl);
  // SIEM-alert.js hace setInterval al importarse: lo capturamos para que no deje el proceso abierto.
  definirGlobal("setInterval", (fn, ms) => {
    temporizadores.push({ fn, ms });
    return temporizadores.length;
  });

  return { dom, temporizadores };
}

let contador = 0;
/** Importa SIEM-alert.js de nuevo (cada import con un parámetro distinto evita la caché de módulos). */
export async function cargarSiemAlert() {
  const url = new URL("SIEM-alert.js", SRC);
  url.searchParams.set("prueba", String(++contador));
  await import(url.href);
  // cargar() es asíncrona y no se exporta: cedemos el turno hasta que termine fetch + pintado.
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
}

export function filasTabla(dom) {
  return [...dom.window.document.querySelectorAll("#tabla tbody tr")].map((tr) => {
    const [sev, titulo, origen, hora] = [...tr.querySelectorAll("td")];
    return {
      severidad: sev.textContent,
      clase: sev.querySelector("span").className,
      titulo: titulo.textContent,
      origen: origen.textContent,
      hora: hora.textContent,
    };
  });
}

import json
import logging
import os
import re
import threading
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, request

SCANNER_URL = os.environ.get("SCANNER_URL", "http://localhost:8004")
DEFAULT_PROFILES = ["vuln"]

app = Flask(__name__)


class _QuietPolling(logging.Filter):
    """Oculta del log de Flask las consultas de la GUI (/api/...)."""
    def filter(self, record):
        return "/api/" not in record.getMessage()


logging.getLogger("werkzeug").addFilter(_QuietPolling())

RECEIVED = []          # eventos recibidos por POST /events
LOCK = threading.Lock()


# ----------------------------------------------------------------------------
# Endpoint que usa el escáner para enviar eventos
# ----------------------------------------------------------------------------
@app.route("/events", methods=["POST"])
def receive_event():
    data = request.get_json(silent=True)
    if data is None:   # cuerpo vacío o no-JSON: lo guardamos tal cual
        data = {"_raw_body": request.get_data(as_text=True),
                "_content_type": request.content_type}
    entry = {"received_at": datetime.now().strftime("%H:%M:%S"), "event": data}
    with LOCK:
        RECEIVED.append(entry)

    print("\n--- [MOCK SIEM] Evento recibido ---")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print("-----------------------------------\n")
    event_id = data.get("event_id") if isinstance(data, dict) else None
    return jsonify({"status": "received", "event_id": event_id}), 200


# ----------------------------------------------------------------------------
# API interna de la GUI (hace de proxy hacia el escáner, evita problemas CORS)
# ----------------------------------------------------------------------------
@app.route("/api/profiles")
def api_profiles():
    """El escáner no expone los perfiles; los descubrimos provocando un 400
    con un perfil inválido, cuyo mensaje de error los lista."""
    try:
        r = requests.post(f"{SCANNER_URL}/scan",
                          json={"target": "x", "profile": "__probe__"}, timeout=5)
        names = re.findall(r"'([^']+)'", r.json().get("error", ""))
        if names:
            return jsonify({"profiles": names, "scanner": "online"})
    except Exception:
        return jsonify({"profiles": DEFAULT_PROFILES, "scanner": "offline"})
    return jsonify({"profiles": DEFAULT_PROFILES, "scanner": "online"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{SCANNER_URL}/scan", json=body, timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": f"No se pudo contactar con el escáner: {e}"}), 502


@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id):
    try:
        r = requests.get(f"{SCANNER_URL}/scan/{scan_id}", timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/received")
def api_received():
    since = int(request.args.get("since", 0))
    with LOCK:
        return jsonify({"total": len(RECEIVED), "items": RECEIVED[since:]})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    with LOCK:
        RECEIVED.clear()
    return jsonify({"ok": True})


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
HTML = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Mock SIEM</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#f5f6f8; --card:#fff; --fg:#1d2330; --mut:#6b7385; --bd:#dde1e8;
          --acc:#2563eb; --code:#0f172a; --codefg:#d6e2ff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151c; --card:#1a1f2b; --fg:#e6e9f0; --mut:#98a1b5; --bd:#2b3243;
            --acc:#4c8dff; --code:#0b0e14; --codefg:#cfe0ff; }
  }
  * { box-sizing:border-box; }
  body { margin:0; font:14px system-ui,sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:14px 22px; border-bottom:1px solid var(--bd); background:var(--card);
           display:flex; justify-content:space-between; align-items:center; }
  h1 { font-size:17px; margin:0; }
  h2 { font-size:13px; margin:0 0 10px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); }
  main { display:grid; grid-template-columns:340px 1fr; gap:16px; padding:16px; }
  @media (max-width:800px) { main { grid-template-columns:1fr; } }
  .card { background:var(--card); border:1px solid var(--bd); border-radius:10px; padding:16px; }
  label { display:block; margin:10px 0 4px; color:var(--mut); font-size:12px; }
  input, select { width:100%; padding:8px 10px; border:1px solid var(--bd); border-radius:6px;
                  background:var(--bg); color:var(--fg); font-size:14px; }
  button { padding:8px 14px; border:0; border-radius:6px; background:var(--acc); color:#fff;
           font-size:14px; cursor:pointer; }
  button.sec { background:transparent; color:var(--fg); border:1px solid var(--bd); }
  button:disabled { opacity:.5; cursor:default; }
  .row { display:flex; gap:8px; margin-top:14px; }
  .badge { font-size:12px; padding:2px 8px; border-radius:10px; border:1px solid var(--bd); color:var(--mut); }
  .on { color:#16a34a; border-color:#16a34a; } .off { color:#dc2626; border-color:#dc2626; }
  #status { margin-top:12px; font-size:13px; color:var(--mut); word-break:break-all; }
  #feed { display:flex; flex-direction:column; gap:10px; max-height:calc(100vh - 150px); overflow:auto; }
  .ev { background:var(--code); border-radius:8px; overflow:hidden; flex:0 0 auto; }
  .ev .hd { padding:6px 12px; font-size:12px; color:#9fb0d0; display:flex; justify-content:space-between; }
  .ev pre { margin:0; padding:4px 12px 12px; color:var(--codefg); font:12.5px ui-monospace,monospace;
            white-space:pre-wrap; word-break:break-word; }
  .empty { color:var(--mut); padding:20px 0; text-align:center; }
</style>
</head>
<body>
<header>
  <h1>Mock SIEM</h1>
  <span id="scanner" class="badge">escáner: …</span>
</header>
<main>
  <section class="card">
    <h2>Lanzar escaneo</h2>
    <label for="target">Target</label>
    <input id="target" placeholder="192.168.1.10 o scanme.nmap.org">
    <label for="profile">Perfil</label>
    <select id="profile"></select>
    <div class="row">
      <button id="go">Ejecutar scan</button>
    </div>
    <div id="status"></div>
  </section>

  <section class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0">Eventos recibidos (<span id="count">0</span>)</h2>
      <button class="sec" id="clear">Limpiar</button>
    </div>
    <div id="feed"><div class="empty" id="empty">Esperando eventos en POST /events…</div></div>
  </section>
</main>

<script>
const $ = id => document.getElementById(id);
let since = 0, pollScan = null;

async function loadProfiles() {
  try {
    const r = await (await fetch('/api/profiles')).json();
    $('profile').innerHTML = r.profiles.map(p => `<option>${p}</option>`).join('');
    const b = $('scanner');
    b.textContent = 'escáner: ' + r.scanner;
    b.className = 'badge ' + (r.scanner === 'online' ? 'on' : 'off');
  } catch (e) {}
}

async function launch() {
  const target = $('target').value.trim();
  if (!target) { $('status').textContent = 'Introduce un target.'; return; }
  $('go').disabled = true;
  $('status').textContent = 'Lanzando…';
  const r = await fetch('/api/scan', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target, profile: $('profile').value})
  });
  const j = await r.json();
  if (!r.ok) {
    $('status').textContent = 'Error: ' + (j.error || r.status);
    $('go').disabled = false; return;
  }
  const id = j.scan_id || j.id;
  $('status').textContent = `Scan ${id} · estado: ${j.status || 'lanzado'}`;
  clearInterval(pollScan);
  if (!id) { $('go').disabled = false; return; }
  pollScan = setInterval(async () => {
    const s = await (await fetch('/api/scan/' + id)).json();
    $('status').textContent = `Scan ${id} · estado: ${s.status || '?'}`;
    if (['done','completed','finished','error','failed'].includes(String(s.status).toLowerCase())) {
      clearInterval(pollScan); $('go').disabled = false;
    }
  }, 2000);
}

async function pollEvents() {
  try {
    const r = await (await fetch('/api/received?since=' + since)).json();
    if (r.total < since) { since = 0; $('feed').innerHTML = ''; }
    if (r.items.length) {
      const e = $('empty'); if (e) e.remove();
      for (const it of r.items) {
        const d = document.createElement('div');
        d.className = 'ev';
        const ev = it.event;
        const isObj = ev && typeof ev === 'object' && !Array.isArray(ev);
        const label = (isObj && (ev.event_id || ev.title)) || 'evento';
        const sev = isObj && ev.severity ? ' · ' + ev.severity : '';
        const hd = document.createElement('div'); hd.className = 'hd';
        const a = document.createElement('span'); a.textContent = label + sev;
        const b = document.createElement('span'); b.textContent = it.received_at;
        hd.append(a, b);
        const pre = document.createElement('pre');
        pre.textContent = JSON.stringify(it.event, null, 2);
        d.append(hd, pre);
        $('feed').prepend(d);
      }
      since = r.total;
      $('count').textContent = since;
    }
  } catch (e) {}
}

$('go').onclick = launch;
$('clear').onclick = async () => {
  await fetch('/api/clear', {method: 'POST'});
  since = 0; $('count').textContent = 0;
  $('feed').innerHTML = '<div class="empty" id="empty">Esperando eventos en POST /events…</div>';
};
loadProfiles();
setInterval(pollEvents, 1000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")


if __name__ == "__main__":
    print(f"[MOCK SIEM] GUI en http://localhost:8005  (escáner: {SCANNER_URL})")
    app.run(host="0.0.0.0", port=8005)

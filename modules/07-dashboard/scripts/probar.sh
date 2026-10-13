#!/usr/bin/env bash
# =============================================================================
# PRUEBA CONJUNTA DEL DASHBOARD (Linux y macOS)
#
# Qué hace, en resumen:
#   1. Comprueba que Docker está disponible.
#   2. Arranca el Dashboard con docker compose (junto con los módulos de los que depende).
#   3. Si ya están en la rama, arranca también los mocks de SOAR y Escáner.
#   4. Espera a que respondan y lanza una serie de comprobaciones (OK / FALLO).
#   5. Al terminar para y borra todo lo que ha arrancado, aunque algo falle.
#
# Garantías: no modifica tu .env, no cambia de rama y no sube nada a GitHub.
#
# Uso (desde cualquier carpeta del clon):  bash modules/07-dashboard/scripts/probar.sh
# Equivalente en Windows: modules\07-dashboard\scripts\probar.ps1
# =============================================================================

# Sin "set -e" a propósito: si una comprobación falla queremos seguir y ver TODOS los fallos,
# no abortar en el primero. "-u" avisa de variables sin definir y "pipefail" propaga errores de tuberías.
set -uo pipefail

# --- Rutas y nombres -----------------------------------------------------------
# RAIZ = raíz del clon, calculada a partir de la ubicación del script (sirve lance donde se lance).
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MOD="$RAIZ/modules/07-dashboard"
# Nombre del "proyecto" de compose: aísla esta prueba de cualquier otro docker compose del equipo.
PROJ=dashprueba
# Copia temporal del .env.example para no tocar el .env real del usuario.
ENVF="$(mktemp "${TMPDIR:-/tmp}/probar-dashboard.XXXXXX")"
# FAIL pasa a 1 si cualquier comprobación falla; es el código de salida final del script.
FAIL=0

# --- Funciones de salida con color ------------------------------------------------
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFALLO\033[0m %s\n' "$1"; FAIL=1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# --- Limpieza -------------------------------------------------------------------
# "trap ... EXIT" ejecuta cleanup SIEMPRE al salir (éxito, fallo o Ctrl+C), para no dejar
# contenedores ni redes colgando que ocupen los puertos en la siguiente prueba.
cleanup() {
  step "Limpiando"
  docker rm -f mock-soar mock-scanner >/dev/null 2>&1 || true
  (cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" down >/dev/null 2>&1) || true
  rm -f "$ENVF"
  echo "  hecho"
}
trap cleanup EXIT

# --- 1. Requisitos --------------------------------------------------------------------
step "Requisitos"
for c in docker curl; do command -v "$c" >/dev/null || { echo "Falta $c"; exit 1; }; done
docker compose version >/dev/null 2>&1 || { echo "Falta 'docker compose' (v2)"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker no responde (¿Docker Desktop/daemon parado o falta permiso/sudo?)"; exit 1; }
ok "docker, compose y curl disponibles"

# --- Utilidades de comprobación ---------------------------------------------------------------
# cuenta URL CLAVE -> cuántas veces aparece "CLAVE": en el JSON que devuelve la URL.
# Sirve para contar elementos (p. ej. cuántas alertas hay) sin depender de python ni de jq.
cuenta() { curl -fs "$1" 2>/dev/null | grep -o "\"$2\":" | wc -l | tr -d ' '; }

# contiene URL TEXTO -> éxito si la respuesta de la URL contiene TEXTO.
# Se guarda primero la respuesta en una variable para evitar fallos de tubería (SIGPIPE) con grep -q.
contiene() { local cuerpo; cuerpo="$(curl -fs "$1" 2>/dev/null)" && grep -q -- "$2" <<<"$cuerpo"; }

# codigo URL -> código HTTP de la respuesta (200, 404...). 000 si no hay conexión.
codigo() { curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }

# --- 2. Variables de entorno -----------------------------------------------------------
# docker compose lee las URLs de los módulos de un fichero de variables. Partimos de .env.example.
cp "$RAIZ/.env.example" "$ENVF"

# --- 3. Arranque del Dashboard ----------------------------------------------------------------------
# "up --build -d dashboard": construye la imagen y arranca el dashboard en segundo plano.
# Por el depends_on del docker-compose también arranca identidad, escáner, siem y soar.
step "Arrancando el Dashboard (docker compose)"
(cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" up --build -d dashboard) \
  || { echo "docker compose falló (¿puertos 8001-8007 ocupados?)"; exit 1; }

# --- 4. Mocks de SOAR y Escáner (solo si ya están en la rama) ------------------------------------
# Los mocks son servicios Flask con datos fijos. Cuando los ficheros existen se construyen y se
# arrancan aparte, en los puertos 5001 (SOAR) y 5002 (Escáner). Si no existen se omiten sin error.
HAY_MOCKS=0
if [ -f "$MOD/mocks/mock_SOAR/app.py" ] && [ -f "$MOD/mocks/mock_scanner/app.py" ]; then
  HAY_MOCKS=1
  step "Arrancando los mocks de SOAR y Escáner"
  docker build -q -t mock-soar "$MOD/mocks/mock_SOAR" >/dev/null && docker run -d --rm --name mock-soar -p 5001:5001 mock-soar >/dev/null || bad "el mock SOAR no arranca"
  docker build -q -t mock-scanner "$MOD/mocks/mock_scanner" >/dev/null && docker run -d --rm --name mock-scanner -p 5002:5002 mock-scanner >/dev/null || bad "el mock Escáner no arranca"
fi

# --- 5. Espera activa ------------------------------------------------------------------------------
# Que el contenedor esté "arrancado" no significa que ya responda. Se sondea /health cada 2 s
# hasta 30 veces (60 s máximo) antes de empezar a comprobar.
step "Esperando a que respondan (máx. 60 s)"
URLS=(http://localhost:8007/health)
[ "$HAY_MOCKS" = 1 ] && URLS+=(http://localhost:5001/health http://localhost:5002/health)
for url in "${URLS[@]}"; do
  for _ in $(seq 1 30); do curl -fs "$url" >/dev/null 2>&1 && break; sleep 2; done
done

# --- 6. Comprobaciones ---------------------------------------------------------------------------------
step "Comprobaciones"

# Dashboard: salud y contenido servido por nginx.
contiene http://localhost:8007/health '"ok"' && ok "dashboard: /health responde 200 (lo que exige el CI)" || bad "dashboard: /health"
contiene http://localhost:8007/ "Dashboard Principal" && ok "dashboard: la página principal se sirve" || bad "dashboard: página principal"

# Login (maqueta): la página existe y la principal está protegida y tiene botón de cierre de sesión.
# OJO: es una maqueta, no consulta a Identidad; aquí solo se comprueba que los ficheros están.
contiene http://localhost:8007/login.html "Acceso CiberURJC" && ok "login: login.html se sirve" || bad "login: falta login.html"
contiene http://localhost:8007/ "login.html" && contiene http://localhost:8007/ "logout" \
  && ok "login: la página principal redirige al login si no hay sesión y tiene cierre de sesión" \
  || bad "login: la página principal no tiene la protección o el botón de cerrar sesión"

# Historias DASHG7-22 y DASHG7-25: datos del mock del SIEM y refresco con hora de actualización.
N=$(cuenta http://localhost:8007/mocks/siem-alerts.json alert_id)
[ "$N" = "4" ] && ok "dashboard: el mock del SIEM tiene 4 alertas" || bad "dashboard: el mock del SIEM devuelve $N alertas (esperaba 4)"
contiene http://localhost:8007/SIEM-alert.js "hora-actualizacion" && ok "dashboard: el JS actualiza la hora de última actualización" || bad "dashboard: falta la actualización de la hora"

# Higiene: el Dockerfile solo debe publicar el mock del SIEM, no el código de los mocks de Python.
[ "$(codigo http://localhost:8007/mocks/mock_SOAR/app.py)" = "404" ] \
  && ok "dashboard: el código de los mocks de Python no se publica en la web" \
  || bad "dashboard: /mocks/mock_SOAR/app.py es accesible desde la web (revisar el Dockerfile)"

# Mocks de SOAR y Escáner (solo si están en la rama): salud y número de elementos.
if [ "$HAY_MOCKS" = 1 ]; then
  contiene http://localhost:5001/health '"ok"' && ok "mock SOAR: /health responde" || bad "mock SOAR: /health"
  N=$(cuenta http://localhost:5001/incidents id)
  [ "$N" = "3" ] && ok "mock SOAR: GET /incidents devuelve 3 incidentes" || bad "mock SOAR: /incidents devuelve $N (esperaba 3)"
  contiene http://localhost:5002/health '"ok"' && ok "mock Escáner: /health responde" || bad "mock Escáner: /health"
  N=$(cuenta http://localhost:5002/findings id)
  [ "$N" = "3" ] && ok "mock Escáner: GET /findings devuelve 3 hallazgos" || bad "mock Escáner: /findings devuelve $N (esperaba 3)"
else
  echo "  (mocks de SOAR y Escáner: aún no están en esta rama; se omiten)"
fi

# --- 7. Resultado y prueba visual ---------------------------------------------------------------------
echo
if [ "$FAIL" = 0 ]; then printf '\033[32mTODO CORRECTO\033[0m\n'; else printf '\033[31mHAY FALLOS (arriba)\033[0m\n'; fi
echo
echo "Prueba visual: abre http://localhost:8007. Te lleva al login: entra con cualquier usuario y contraseña."
echo "Después deberías ver 4 alertas ordenadas por severidad, la hora real en 'Última actualización'"
echo "(cambia sola cada 30 s) y el botón 'Cerrar Sesión', que te devuelve al login."
# Si el script se lanza en una terminal interactiva, espera a que pulses Enter para dejarte mirar
# el navegador antes de limpiar. Si no hay terminal (CI, redirecciones), limpia directamente.
if [ -t 0 ]; then read -r -p "Pulsa Enter para parar todo y limpiar... " _; fi
exit "$FAIL"

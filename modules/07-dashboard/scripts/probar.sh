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
# Uso (desde cualquier carpeta del clon):  bash modules/07-dashboard/scripts/probar.sh [opciones]
# Equivalente en Windows: modules\07-dashboard\scripts\probar.ps1
#
# Opciones (ver "probar.sh -h"):
#   -s  no reconstruir las imágenes (demo rápida)      -m  dejar todo levantado al terminar
#   -c  solo comprobar lo que ya está corriendo        -p  parar lo que dejó -m
#   -n  sin los mocks de SOAR y Escáner                -h  ayuda
# =============================================================================

# --- Ayuda ----------------------------------------------------------------------------------
uso() {
  cat <<'EOF'
Uso: bash modules/07-dashboard/scripts/probar.sh [opciones]

Sin opciones: construye (con la caché de Docker), arranca, comprueba y limpia al terminar.

  -s, --sin-build       No reconstruye: usa las imágenes que ya existen (solo construye las que falten).
                        Aviso: tras un "git pull" con cambios, ejecuta antes SIN opciones; si no, puedes
                        probar una imagen antigua y obtener un OK que no corresponde.
  -m, --mantener        Al terminar no para nada: deja todo levantado y no espera a Enter.
  -c, --solo-comprobar  No arranca ni construye nada: solo ejecuta las comprobaciones sobre lo que ya
                        esté corriendo (arráncalo antes con -m, o sin opciones en otra terminal).
  -p, --parar           Para y borra lo que dejó -m (contenedores, red y mocks). No hace pruebas.
  -n, --sin-mocks       No arranca ni comprueba los mocks de SOAR y Escáner.
  -h, --ayuda           Muestra esta ayuda.

Las opciones se escriben por separado (-s -m, no -sm).

Flujo recomendado para la demo:
  1) Un rato antes, una vez:   probar.sh            (construye y deja las imágenes guardadas)
  2) En la demo:               probar.sh -s         (no reconstruye; arranca, comprueba y espera)
  3) Si lo quieres ya levantado: probar.sh -s -m    y luego  probar.sh -c   y al final  probar.sh -p
EOF
}

# --- Opciones ---------------------------------------------------------------------------------
# Cada opción activa una variable (0 = desactivada, 1 = activada). Se interpretan antes de tocar
# nada, para que "-h" o una opción errónea no arranquen Docker ni creen ficheros.
SIN_BUILD=0; MANTENER=0; SOLO_COMPROBAR=0; PARAR=0; SIN_MOCKS=0
for arg in "$@"; do
  case "$arg" in
    -s|--sin-build)       SIN_BUILD=1 ;;
    -m|--mantener)        MANTENER=1 ;;
    -c|--solo-comprobar)  SOLO_COMPROBAR=1 ;;
    -p|--parar)           PARAR=1 ;;
    -n|--sin-mocks)       SIN_MOCKS=1 ;;
    -h|--ayuda|--help)    uso; exit 0 ;;
    *) echo "Opción desconocida: $arg" >&2; echo >&2; uso >&2; exit 2 ;;
  esac
done

# Sin "set -e" a propósito: si una comprobación falla queremos seguir y ver TODOS los fallos,
# no abortar en el primero. "-u" avisa de variables sin definir y "pipefail" propaga errores de tuberías.
set -uo pipefail

# --- Rutas y nombres -----------------------------------------------------------
# RAIZ = raíz del clon, calculada a partir de la ubicación del script (sirve lance donde se lance).
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MOD="$RAIZ/modules/07-dashboard"
# Nombre del "proyecto" de compose: aísla esta prueba de cualquier otro docker compose del equipo
# y hace que las imágenes se llamen siempre igual (dashprueba-*), de modo que -s las reutilice.
PROJ=dashprueba
# Copia temporal del .env.example para no tocar el .env real del usuario.
ENVF="$(mktemp "${TMPDIR:-/tmp}/probar-dashboard.XXXXXX")"
# FAIL pasa a 1 si cualquier comprobación falla; es el código de salida final del script.
FAIL=0
# ARRANCADO = 1 si ESTA ejecución ha levantado contenedores. LIMPIAR = 1 si hay que pararlos al salir.
# Así nunca se tira abajo algo que otra ejecución (por ejemplo con -m) dejó levantado a propósito.
ARRANCADO=0
LIMPIAR=1
{ [ "$MANTENER" = 1 ] || [ "$SOLO_COMPROBAR" = 1 ]; } && LIMPIAR=0

# --- Funciones de salida con color ------------------------------------------------
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFALLO\033[0m %s\n' "$1"; FAIL=1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# --- Limpieza -------------------------------------------------------------------
# "trap ... EXIT" ejecuta cleanup SIEMPRE al salir (éxito, fallo o Ctrl+C), para no dejar
# contenedores ni redes colgando que ocupen los puertos en la siguiente prueba.
# Solo para lo que arrancó esta ejecución y solo si no se pidió -m; con -m avisa de cómo pararlo.
parar_todo() {
  docker rm -f mock-soar mock-scanner >/dev/null 2>&1 || true
  (cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" down >/dev/null 2>&1) || true
}
cleanup() {
  if [ "$ARRANCADO" = 1 ] && [ "$LIMPIAR" = 1 ]; then
    step "Limpiando"
    parar_todo
    echo "  hecho"
  elif [ "$ARRANCADO" = 1 ]; then
    echo
    echo "Todo sigue levantado (-m). Para pararlo:  bash modules/07-dashboard/scripts/probar.sh -p"
  fi
  rm -f "$ENVF"
}
trap cleanup EXIT

# --- 1. Requisitos --------------------------------------------------------------------
# Con -c solo hace falta curl (no se toca Docker). En el resto de modos también Docker.
step "Requisitos"
command -v curl >/dev/null || { echo "Falta curl"; exit 1; }
if [ "$SOLO_COMPROBAR" = 0 ]; then
  command -v docker >/dev/null || { echo "Falta docker"; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "Falta 'docker compose' (v2)"; exit 1; }
  docker info >/dev/null 2>&1 || { echo "Docker no responde (¿Docker Desktop/daemon parado o falta permiso/sudo?)"; exit 1; }
  ok "docker, compose y curl disponibles"
else
  ok "curl disponible (modo solo-comprobar: no se usa Docker)"
fi

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

# --- Modo -p: parar lo que dejó -m y salir ---------------------------------------------------------
if [ "$PARAR" = 1 ]; then
  step "Parando lo que dejó -m"
  parar_todo
  echo "  hecho (contenedores, red y mocks eliminados; las imágenes se conservan)"
  exit 0
fi

# --- ¿Hay mocks que probar? ------------------------------------------------------------------------
# Los mocks de SOAR y Escáner (servicios Flask con datos fijos) solo se prueban si sus ficheros están
# en la rama y no se pidió -n.
HAY_MOCKS=0
if [ "$SIN_MOCKS" = 0 ] && [ -f "$MOD/mocks/mock_SOAR/app.py" ] && [ -f "$MOD/mocks/mock_scanner/app.py" ]; then
  HAY_MOCKS=1
fi

# --- 3. Arranque (se salta con -c) -------------------------------------------------------------------
if [ "$SOLO_COMPROBAR" = 0 ]; then
  # Protección: si ya hay una prueba levantada (por ejemplo con -m), no se arranca otra encima
  # porque los puertos chocarían; se indica qué hacer.
  if [ -n "$(cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" ps -q dashboard 2>/dev/null)" ]; then
    echo "Ya hay una prueba en marcha (proyecto $PROJ)."
    echo "Usa -c para solo comprobar lo que hay, o -p para pararla antes de volver a arrancar."
    exit 1
  fi

  # "up -d dashboard" arranca el dashboard en segundo plano; por su depends_on arrastra también
  # identidad, escáner, siem y soar. Con --build reconstruye las imágenes (usando la caché de Docker);
  # con -s se omite y solo se construyen las que no existan todavía.
  BUILD=(--build); [ "$SIN_BUILD" = 1 ] && BUILD=()
  step "Arrancando el Dashboard (docker compose$([ "$SIN_BUILD" = 1 ] && echo ', sin reconstruir'))"
  ARRANCADO=1
  # (${BUILD[@]+...} evita el error de "variable sin definir" con un array vacío en el bash antiguo de macOS)
  if ! (cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" up ${BUILD[@]+"${BUILD[@]}"} -d dashboard); then
    echo "docker compose falló (¿puertos 8001-8007 ocupados?)"
    LIMPIAR=1   # aunque se pidiera -m, si el arranque falla no dejamos restos a medias
    exit 1
  fi

  # Mocks: se construyen (salvo con -s y si la imagen ya existe) y se arrancan aparte, en los
  # puertos 5001 (SOAR) y 5002 (Escáner). Si ya están corriendo, se reutilizan.
  # arrancar_mock NOMBRE IMAGEN CARPETA PUERTO
  arrancar_mock() {
    local nombre="$1" imagen="$2" dir="$3" puerto="$4"
    if docker ps --format '{{.Names}}' | grep -qx "$nombre"; then
      echo "  $nombre ya está en marcha; se reutiliza"; return 0
    fi
    docker rm -f "$nombre" >/dev/null 2>&1 || true
    if ! { [ "$SIN_BUILD" = 1 ] && docker image inspect "$imagen" >/dev/null 2>&1; }; then
      docker build -q -t "$imagen" "$dir" >/dev/null || return 1
    fi
    docker run -d --rm --name "$nombre" -p "$puerto:$puerto" "$imagen" >/dev/null
  }
  if [ "$HAY_MOCKS" = 1 ]; then
    step "Arrancando los mocks de SOAR y Escáner"
    arrancar_mock mock-soar    mock-soar    "$MOD/mocks/mock_SOAR"    5001 || bad "el mock SOAR no arranca"
    arrancar_mock mock-scanner mock-scanner "$MOD/mocks/mock_scanner" 5002 || bad "el mock Escáner no arranca"
  fi

  # --- 4. Espera activa ------------------------------------------------------------------------------
  # Que el contenedor esté "arrancado" no significa que ya responda. Se sondea /health cada 2 s
  # hasta 30 veces (60 s máximo) antes de empezar a comprobar.
  step "Esperando a que respondan (máx. 60 s)"
  URLS=(http://localhost:8007/health)
  [ "$HAY_MOCKS" = 1 ] && URLS+=(http://localhost:5001/health http://localhost:5002/health)
  for url in "${URLS[@]}"; do
    for _ in $(seq 1 30); do curl -fs "$url" >/dev/null 2>&1 && break; sleep 2; done
  done
else
  # Con -c no se arranca nada: si el Dashboard no responde, se avisa en lugar de dar fallos en cadena.
  if ! curl -fs http://localhost:8007/health >/dev/null 2>&1; then
    echo "El Dashboard no responde en localhost:8007. Arráncalo antes (sin -c, o con -m) y vuelve a probar."
    exit 1
  fi
fi

# --- 5. Comprobaciones ---------------------------------------------------------------------------------
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

# Proxy hacia el SIEM real (nginx reenvía /api/siem/ a siem:80 por la red de Docker). Es lo que usa la web
# (SIEM-client.js), así que se comprueba que el JS apunta al proxy, que el proxy llega al SIEM y que solo
# deja pasar GET. No se cuenta el número de alertas: depende de lo que tenga el SIEM en ese momento.
contiene http://localhost:8007/SIEM-client.js "/api/siem/alerts" && ok "dashboard: el JS pide las alertas al proxy /api/siem/alerts" || bad "dashboard: SIEM-client.js no apunta a /api/siem/alerts"
[ "$(codigo http://localhost:8007/api/siem/alerts)" = "200" ] && contiene http://localhost:8007/api/siem/alerts '"alerts"' \
  && ok "dashboard: el proxy /api/siem/alerts llega al SIEM (200 con {\"alerts\": [...]})" \
  || bad "dashboard: /api/siem/alerts no responde 200 con alertas (¿SIEM caído o proxy mal configurado? 502 = SIEM no alcanzable)"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8007/api/siem/alerts 2>/dev/null)" = "403" ] \
  && ok "dashboard: el proxy rechaza métodos distintos de GET (403)" \
  || bad "dashboard: el proxy deja pasar métodos distintos de GET (revisar limit_except en default.conf)"

# Higiene: el Dockerfile solo debe publicar el mock del SIEM, no el código de los mocks de Python.
[ "$(codigo http://localhost:8007/mocks/mock_SOAR/app.py)" = "404" ] \
  && ok "dashboard: el código de los mocks de Python no se publica en la web" \
  || bad "dashboard: /mocks/mock_SOAR/app.py es accesible desde la web (revisar el Dockerfile)"

# Mocks de SOAR y Escáner (solo si están en la rama y no se pidió -n): salud y número de elementos.
if [ "$HAY_MOCKS" = 1 ]; then
  contiene http://localhost:5001/health '"ok"' && ok "mock SOAR: /health responde" || bad "mock SOAR: /health"
  N=$(cuenta http://localhost:5001/incidents incident_id)
  [ "$N" = "3" ] && ok "mock SOAR: GET /incidents devuelve 3 incidentes" || bad "mock SOAR: /incidents devuelve $N (esperaba 3)"
  contiene http://localhost:5002/health '"ok"' && ok "mock Escáner: /health responde" || bad "mock Escáner: /health"
  N=$(cuenta http://localhost:5002/events scan_id)
  [ "$N" = "2" ] && ok "mock Escáner: GET /events devuelve 2 escaneos" || bad "mock Escáner: /events devuelve $N (esperaba 2)"
elif [ "$SIN_MOCKS" = 1 ]; then
  echo "  (mocks de SOAR y Escáner: omitidos por -n)"
else
  echo "  (mocks de SOAR y Escáner: no están en esta rama; se omiten)"
fi

# --- 6. Resultado y prueba visual ---------------------------------------------------------------------
echo
if [ "$FAIL" = 0 ]; then printf '\033[32mTODO CORRECTO\033[0m\n'; else printf '\033[31mHAY FALLOS (arriba)\033[0m\n'; fi
echo
echo "Prueba visual: abre http://localhost:8007. Te lleva al login: entra con cualquier usuario y contraseña."
echo "Después deberías ver las alertas reales del SIEM ordenadas por severidad (si el SIEM no tiene ninguna,"
echo "la lista sale vacía), la hora real en 'Última actualización' (cambia sola cada 30 s) y el botón"
echo "'Cerrar Sesión', que te devuelve al login."
# Solo se pausa si el script arrancó él mismo los contenedores y los va a limpiar: así puedes mirar
# el navegador antes de que se paren. Con -m o -c no hay nada que limpiar, así que no se espera.
# Si no hay terminal interactiva (CI, redirecciones) tampoco se espera.
if [ "$LIMPIAR" = 1 ] && [ "$ARRANCADO" = 1 ] && [ -t 0 ]; then read -r -p "Pulsa Enter para parar todo y limpiar... " _; fi
exit "$FAIL"

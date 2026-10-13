#!/usr/bin/env bash
# Prueba conjunta del Dashboard: arranca el contenedor con docker compose, comprueba que responde
# y, si ya están en la rama, prueba también los mocks de SOAR y Escáner.
# No toca tu .env ni deja nada arrancado al terminar.
#
# Uso (desde cualquier carpeta del clon):  bash modules/07-dashboard/scripts/probar.sh
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MOD="$RAIZ/modules/07-dashboard"
PROJ=dashprueba
ENVF="$(mktemp)"
FAIL=0

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
bad()  { printf '  \033[31mFALLO\033[0m %s\n' "$1"; FAIL=1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

cleanup() {
  step "Limpiando"
  docker rm -f mock-soar mock-scanner >/dev/null 2>&1 || true
  (cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" down >/dev/null 2>&1) || true
  rm -f "$ENVF"
  echo "  hecho"
}
trap cleanup EXIT

step "Requisitos"
for c in docker curl python3; do command -v "$c" >/dev/null || { echo "Falta $c"; exit 1; }; done
docker compose version >/dev/null 2>&1 || { echo "Falta 'docker compose' (v2)"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker no responde (¿daemon parado o falta permiso/sudo?)"; exit 1; }
ok "docker, compose, curl y python3 disponibles"

# Variables: se parte de .env.example en un fichero temporal, así no se pisa el .env del usuario.
cp "$RAIZ/.env.example" "$ENVF"

step "Arrancando el Dashboard (docker compose)"
(cd "$RAIZ" && docker compose --env-file "$ENVF" -p "$PROJ" up --build -d dashboard) \
  || { echo "docker compose falló (¿puertos 8001-8007 ocupados?)"; exit 1; }

HAY_MOCKS=0
if [ -f "$MOD/mocks/mock_SOAR/app.py" ] && [ -f "$MOD/mocks/mock_scanner/app.py" ]; then
  HAY_MOCKS=1
  step "Arrancando los mocks de SOAR y Escáner"
  docker build -q -t mock-soar "$MOD/mocks/mock_SOAR" >/dev/null && docker run -d --rm --name mock-soar -p 5001:5001 mock-soar >/dev/null || bad "el mock SOAR no arranca"
  docker build -q -t mock-scanner "$MOD/mocks/mock_scanner" >/dev/null && docker run -d --rm --name mock-scanner -p 5002:5002 mock-scanner >/dev/null || bad "el mock Escáner no arranca"
fi

step "Esperando a que respondan (máx. 60 s)"
URLS=(http://localhost:8007/health)
[ "$HAY_MOCKS" = 1 ] && URLS+=(http://localhost:5001/health http://localhost:5002/health)
for url in "${URLS[@]}"; do
  for _ in $(seq 1 30); do curl -fs "$url" >/dev/null 2>&1 && break; sleep 2; done
done

step "Comprobaciones"
curl -fs http://localhost:8007/health | grep -q '"ok"' && ok "dashboard: /health responde 200" || bad "dashboard: /health"
curl -fs http://localhost:8007/ | grep -q "Dashboard Principal" && ok "dashboard: la página principal se sirve" || bad "dashboard: página principal"
N=$(curl -fs http://localhost:8007/mocks/siem-alerts.json | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["alerts"]))' 2>/dev/null || echo 0)
[ "$N" = "4" ] && ok "dashboard: el mock del SIEM tiene 4 alertas" || bad "dashboard: el mock del SIEM devuelve $N alertas (esperaba 4)"
curl -fs http://localhost:8007/SIEM-alert.js | grep -q "hora-actualizacion" && ok "dashboard: el JS actualiza la hora de última actualización" || bad "dashboard: falta la actualización de la hora"
if [ "$HAY_MOCKS" = 1 ]; then
  N=$(curl -fs http://localhost:5001/incidents | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
  [ "$N" = "3" ] && ok "mock SOAR: GET /incidents devuelve 3 incidentes" || bad "mock SOAR: /incidents devuelve $N (esperaba 3)"
  N=$(curl -fs http://localhost:5002/findings | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
  [ "$N" = "3" ] && ok "mock Escáner: GET /findings devuelve 3 hallazgos" || bad "mock Escáner: /findings devuelve $N (esperaba 3)"
else
  echo "  (mocks de SOAR y Escáner: aún no están en esta rama; se omiten)"
fi

echo
if [ "$FAIL" = 0 ]; then printf '\033[32mTODO CORRECTO\033[0m\n'; else printf '\033[31mHAY FALLOS (arriba)\033[0m\n'; fi
echo
echo "Abre http://localhost:8007: 4 alertas ordenadas por severidad y hora real en 'Última actualización'."
if [ -t 0 ]; then read -r -p "Pulsa Enter para parar todo y limpiar... " _; fi
exit "$FAIL"

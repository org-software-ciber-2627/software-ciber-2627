# Módulo 4 · Escáner de vulnerabilidades

- **Equipo propietario:** `equipo-04-escaner`
- **Puerto:** `8004`

## Qué expone
El módulo proporciona una API REST en Flask encargada de orquestar escaneos de seguridad mediante Nmap, procesar los resultados y exponer la información para el Dashboard y el SIEM.

### Endpoints disponibles:

- **`POST /scan`**
  - **Descripción:** Crea un escaneo en segundo plano para el objetivo (`target`) y el perfil seleccionado (`profile`). Responde con `200 OK`, un `scan_id` y estado `running`; el resultado se consulta después con `GET /scan/<scan_id>`.
  - **Parámetros JSON de entrada:** `target` (IP, rango o dominio) y opcionalmente `profile` (`vuln`, `web`, `quick`).

- **`GET /scan/<scan_id>`**
  - **Descripción:** Permite consultar el estado (`running`, `completed` o `failed`) y los eventos. Cuando falla, incluye un campo `error`.

- **`GET /scans`** o **`GET /events`** *(Catálogo de escaneos)*
  - **Descripción:** Devuelve un listado con el histórico de escaneos realizados. `/events` es un alias de `/scans`.

- **`GET /diff`**
  - **Descripción:** Compara dos escaneos distintos mediante los parámetros de la URL (`?base=ID1&target=ID2`) para identificar vulnerabilidades nuevas, resueltas y persistentes.

- **`GET /scans/<scan_id>/report`** *(Informe del Dashboard)*
  - **Descripción:** Devuelve únicamente los hallazgos de vulnerabilidad de un escaneo terminado. Los eventos `cve_detected` se presentan como `vulnerability_detected` para el Dashboard.

La publicación hacia el SIEM es una petición saliente del escáner a `SIEM_URL` y no un endpoint de recepción de este módulo.

## Qué consume
- Herramienta externa **Nmap** para la ejecución de los análisis de seguridad y scripts NSE.

## Perfil `vuln` (--script vuln)

El perfil está documentado en [`docs/perfil_vuln.md`](docs/perfil_vuln.md), incluidos los límites de ejecución, el formato de hallazgos y las limitaciones de cobertura.


## Estado
API funcional implementada en Python con Flask, adaptada para funcionar dentro de la arquitectura de contenedores del proyecto.

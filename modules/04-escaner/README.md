# Módulo 4 · Escáner de vulnerabilidades

- **Equipo propietario:** `equipo-04-escaner`
- **Puerto:** `8004`

## Qué expone
El módulo proporciona una API REST en Flask encargada de orquestar escaneos de seguridad mediante Nmap, procesar los resultados y exponer la información para el Dashboard y el SIEM.

### Endpoints disponibles:

- **`POST /scan`**
  - **Descripción:** Lanza un nuevo escaneo de vulnerabilidades contra el objetivo (`target`) especificado utilizando el perfil seleccionado (`profile`). Ejecuta Nmap, parsea el informe XML resultante y devuelve el resultado completo de forma síncrona con un código `200 OK`.
  - **Parámetros JSON de entrada:** `target` (IP, rango o dominio) y opcionalmente `profile` (`vuln`, `web`, `quick`).

- **`GET /scan/<scan_id>`**
  - **Descripción:** Permite consultar los detalles completos y el estado actual de un escaneo específico a partir de su identificador único (`scan_id`).

- **`GET /history`** *(Histórico de escaneos)*
  - **Descripción:** Devuelve un listado con el histórico completo de todos los escaneos realizados hasta el momento, facilitando la visualización general de la actividad de auditoría para el Dashboard.

- **`GET /diff`**
  - **Descripción:** Compara dos escaneos distintos mediante los parámetros de la URL (`?base=ID1&target=ID2`) para identificar vulnerabilidades nuevas, resueltas y persistentes.

- **`POST /events`** *(Receptor SIEM / Mock)*
  - **Descripción:** método mediante el cual el escáner publica los eventos hacia el SIEM. No es un método accesible para los usuarios del escáner, pero se emplea para enviar los resultados automáticamente al SIEM                         tras el escaneo. 

## Qué consume
- Herramienta externa **Nmap** para la ejecución de los análisis de seguridad y scripts NSE.

## Perfil `vuln` (--script vuln)

El perfil `vuln` ejecuta Nmap con `-sT -sV --script vuln` y los puertos TCP predeterminados de Nmap. La categoría NSE `vuln` comprueba servicios detectados frente a vulnerabilidades conocidas; el escaneo puede tardar más que los perfiles `quick` y `web`.

Un hallazgo se representa como evento cuando la salida del script indica vulnerabilidad o incluye un CVE, salvo que indique explícitamente `NOT VULNERABLE`. Se procesan scripts asociados a puertos y scripts a nivel de host. Cada evento sigue el contrato del SIEM: `source: scanner`, y los datos del objetivo, script, evidencia, escaneo, CVE y CVSS se guardan dentro de `details`. Si no hay CVSS, el evento se conserva con severidad `medium`; en caso contrario la severidad se deriva de la puntuación.

Este perfil es de detección y genera tráfico de comprobación contra el objetivo. Debe utilizarse únicamente con objetivos autorizados. Los resultados dependen de los servicios accesibles, las versiones identificadas y los scripts NSE disponibles en la instalación de Nmap.


## Estado
API funcional implementada en Python con Flask, adaptada para funcionar dentro de la arquitectura de contenedores del proyecto.

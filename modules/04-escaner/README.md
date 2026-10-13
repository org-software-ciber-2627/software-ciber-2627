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

## Estado
API funcional implementada en Python con Flask, adaptada para funcionar dentro de la arquitectura de contenedores del proyecto.

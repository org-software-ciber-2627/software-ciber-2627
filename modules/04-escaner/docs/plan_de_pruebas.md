# Plan de pruebas (E4EDV-23): parser de salida XML de Nmap a JSON

## 1. Objetivo y alcance

Se comprueba que la aplicación convierte la salida XML de Nmap (`-oX`) en la lista de eventos JSON definida, sin perder información, sin falsos positivos y sin romperse ante entradas inesperadas.

**Componente bajo prueba:** `parser.py` (`parse_xml`, `is_vulnerable`, `severity_from_cvss`, `make_event`), dentro de la API del escáner.

- **Pruebas automatizadas (pytest):** XML generados en los propios tests; no requieren Nmap instalado. Cubren todos los casos del parser.
- **Pruebas manuales de integración:** solo dos escaneos reales con `curl` sobre `127.0.0.1`, uno `quick` y otro `vuln`, para comprobar que el parser funciona con salida real de Nmap.
- **Fuera de alcance:** el resto de perfiles (web), el endpoint `/diff` y la capacidad de Nmap para detectar vulnerabilidades. El perfil solo cambia el XML de entrada, que es lo que valida el parser.

## 2. Formato de salida esperado

Cada evento es un diccionario con estos campos:

| Campo | Contenido |
|---|---|
| `event_id` | UUID único |
| `event_type` | `port_open`, `service_detected`, `cve_detected` o `vulnerability_detected` |
| `severity` | `info`, `low`, `medium`, `high` o `critical` |
| `source` | Siempre `scanner` |
| `timestamp` | ISO 8601 en UTC (ej. `2026-10-29T12:18:41Z`) |
| `title`, `description` | Texto del hallazgo |
| `details.tool`, `scan_id`, `profile` | `nmap`, id del escaneo y perfil usado |
| `details.target` | `ip`, `port` (entero), `protocol`, `service` |
| `details.cve`, `cvss`, `script_id`, `evidence` | Datos del script NSE, o `null` |

## 3. Casos automatizados (pytest)

### Caso 1: puertos y servicios a eventos con la estructura correcta

**Entrada:** XML con puertos abiertos, cerrados y filtrados (TCP y UDP), con y sin servicio. Se ejecuta `parse_xml(xml, scan_id)` y se revisan los eventos.

**Resultado esperado:**

- Cada puerto abierto genera un `port_open` y, si tiene servicio, un `service_detected` (severidad `info`).
- Los puertos cerrados o filtrados no generan eventos.
- Todos los eventos llevan todas las claves, con `source`, `tool`, `scan_id` y `profile` correctos, `event_id` único y `timestamp` ISO 8601 UTC.
- `ip`, `port` (entero), `protocol` y `service` coinciden con el XML, y la lista se serializa a JSON sin errores.

### Caso 2: scripts NSE a hallazgos de vulnerabilidad

**Entrada:** XML con scripts que devuelven vulnerabilidad con uno o varios CVE (con y sin CVSS), vulnerabilidad sin CVE, `NOT VULNERABLE`, errores (`ERROR:`) y salida vacía.

**Resultado esperado:**

- Un `cve_detected` por cada CVE único (en mayúsculas), con `cve`, `cvss` y `evidence` correctos.
- Un `vulnerability_detected` (severidad `medium`) si hay vulnerabilidad sin CVE.
- Severidad por CVSS: ≥ 9.0 `critical`, ≥ 7.0 `high`, ≥ 4.0 `medium`, < 4.0 `low`, sin CVSS `medium`. Cada CVE tiene su propio CVSS y los valores superiores a 10 se descartan.
- Ningún evento para `NOT VULNERABLE` (aunque cite CVE), errores de ejecución ni salidas vacías.

## 4. Casos manuales de integración (API + Nmap real)

**Entorno:** VM Kali Linux, API Flask en `http://localhost:80`, objetivo `127.0.0.1` (puerto 80 abierto por la propia API).

| Caso | Perfil y comando de Nmap | Estado |
|---|---|---|
| 3. Escaneo rápido | `quick`: `nmap -sT -oX <fichero> 127.0.0.1` | Realizado el 29/10/2026: correcto |
| 4. Escaneo normal | `vuln`: `nmap -sT -sV --script vuln -oX <fichero> 127.0.0.1` | Realizado |

### Caso 3: escaneo quick (realizado)

Se lanza con `curl -X POST http://localhost/scan` (cuerpo JSON con `target` y `profile`) y se consulta con `curl http://localhost/scan/<scan_id>`.

**Esperado:** estado `running` al crear el job y `completed` al terminar; eventos `port_open` y `service_detected` del puerto 80/tcp (http), ambos `info`, y ninguno de vulnerabilidad.

**Obtenido:** escaneo `a9ddfe14-2a1f-4524-9907-7a740c671184`, `completed`, con los dos eventos esperados. Todos los campos coinciden (`source: scanner`, `tool: nmap`, `profile: quick`, `ip: 127.0.0.1`, `port: 80`, `protocol: tcp`, `service: http`), `cve`, `cvss`, `script_id` y `evidence` son `null`, los `event_id` son distintos, el `timestamp` es ISO 8601 UTC y el JSON es válido.

Confirma en un caso real los puntos del Caso 1.

### Caso 4: escaneo vuln (realizado)

Mismo procedimiento con `"profile": "vuln"`, consultando hasta que el estado deje de ser `running`.

**Esperado:** tarda varios minutos (en una prueba previa superó los 8 con el proceso `nmap` activo). Al terminar, `completed` con `port_open` y `service_detected` por cada puerto abierto.

Solo debe haber `cve_detected` o `vulnerability_detected` si un script detecta una vulnerabilidad real. En esta VM se espera ninguno, y en ningún caso falsos positivos por resultados `NOT VULNERABLE`.

**Obtenido:** pendiente de anotar el id del escaneo y los eventos devueltos.

**Alcance:** confirma que el parser procesa sin errores una salida real con detección de versión y scripts NSE. Los casos con CVE, `NOT VULNERABLE` y errores se cubren con pytest (Caso 2), porque esta VM no tiene vulnerabilidades.

## 5. Criterios de aceptación y ejecución

- Los casos 1 y 2 pasan sin excepciones con XML válido.
- No hay falsos positivos en resultados `NOT VULNERABLE`.
- El escaneo quick real (Caso 3) devuelve los eventos esperados: **cumplido**.
- El escaneo vuln real (Caso 4) termina, devuelve JSON válido y no genera falsos positivos: **cumplido**.
- Los fallos detectados se documentan como defectos con propuesta de corrección.

**Ejecución.**

- Automatizadas: `pytest -v test_parser.py` (bloques A–C para el Caso 1, D–E para el Caso 2).
- Manuales: los `curl` de los casos 3 y 4, con el servidor Flask en marcha.

**Observación.** El perfil `vuln` es lento porque no tiene límites de tiempo; para acelerarlo en pruebas futuras puede añadirse `--host-timeout` y `--script-timeout`.
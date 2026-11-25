# E4EDV-32 / E4EDV-37 · Comportamiento y límites del perfil `vuln`

## Propósito

El perfil `vuln` combina detección de servicios (`-sV`) con los scripts de la categoría NSE `vuln`. Su objetivo es señalar posibles vulnerabilidades conocidas en los servicios accesibles al escáner y devolver resultados que puedan consultar el Dashboard y el SIEM.

El perfil genera tráfico activo de comprobación. Debe ejecutarse únicamente contra sistemas propios o para los que se tenga autorización.

## Ejecución

El comando se construye como una lista de argumentos (sin shell):

```text
nmap -sT -sV --script vuln --script-timeout 60s --host-timeout 15m -oX <informe.xml> <objetivo>
```

Los valores se pueden ajustar en el contenedor mediante `NMAP_VULN_SCRIPT_TIMEOUT` y `NMAP_VULN_HOST_TIMEOUT`. El proceso completo tiene un límite de 1200 segundos, configurable con `NMAP_TIMEOUT_SECONDS`. Si se alcanza, se termina el proceso y el trabajo queda en estado `failed`.

`POST /scan` acepta `target` y `profile`. Si no se indica el perfil, usa `vuln`. Los perfiles aceptados son `vuln`, `web` y `quick`. La respuesta incluye `scan_id` y estado `running`; consulta `GET /scan/<scan_id>` hasta que el estado sea `completed` o `failed`.

## Conversión de resultados

Se procesa el XML de Nmap y se generan eventos comunes:

- Cada puerto abierto genera `port_open`; si Nmap identifica un servicio, también `service_detected`.
- Los scripts NSE asociados a un puerto y los scripts a nivel de host se inspeccionan como posibles hallazgos.
- Una salida que indica `VULNERABLE` o incluye una referencia CVE genera un hallazgo. Si incluye CVE, se genera un evento por CVE único; si no, se genera `vulnerability_detected` con severidad `medium`.
- Una salida que indica explícitamente `NOT VULNERABLE`, está vacía o contiene `ERROR:` no genera hallazgos de vulnerabilidad.
- El CVSS se conserva si es válido (0–10) y determina la severidad: `<4` baja, `4–<7` media, `7–<9` alta, `≥9` crítica. Sin CVSS, la severidad es media.

Todos los eventos siguen el contrato compartido: `source: scanner`, `event_id`, `timestamp` UTC, `event_type`, `severity`, título y descripción. El SIEM admite `low`, `medium`, `high` y `critical`; por eso los eventos informativos de puerto y servicio usan `low`. `details` incluye objetivo, puerto/protocolo/servicio (nulos para un script de host), herramienta, perfil, `scan_id`, script, evidencia, CVE y CVSS. Los eventos se envían al SIEM como eventos originales. El informe del Dashboard filtra los eventos informativos y presenta `cve_detected` como `vulnerability_detected`.

## Limitaciones

- Un resultado sin hallazgos no demuestra que el objetivo esté libre de vulnerabilidades. Depende de que el host sea detectable, los puertos y servicios sean accesibles, Nmap identifique correctamente sus versiones y la instalación disponga de los scripts NSE pertinentes.
- El límite de tiempo puede dejar un escaneo incompleto. Un host o script que exceda sus límites puede no producir todos los resultados.
- NSE puede producir resultados informativos o falsos positivos; cada hallazgo debe revisarse con la evidencia del script.
- Los trabajos se almacenan en memoria y se pierden al reiniciar el servicio. El envío al SIEM se intenta una vez por evento; un fallo de conexión no cancela el escaneo y no se reintenta automáticamente.
- `quick` y `web` usan conjuntos de argumentos distintos; esta política y los scripts seleccionados para `web` están documentados por separado en `perfil_web_scripts_nse.md`.

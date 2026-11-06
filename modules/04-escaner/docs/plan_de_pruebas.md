# E4EDV-38 · Verificación del perfil `vuln`

## Alcance

Se verifica el flujo desde la selección del perfil en `POST /scan`, la construcción y ejecución de Nmap, el parseo del informe XML y la producción de eventos para el SIEM y el Dashboard. Las pruebas automatizadas usan XML y procesos simulados: no ejecutan escaneos contra redes.

## Casos automatizados

Desde `modules/04-escaner/src`:

```bash
python -m unittest -v test_runner test_parser test_jobs test_catalogo test_reports
```

| Caso | Resultado esperado |
|---|---|
| Construcción de comando | El perfil `vuln` incluye detección de versiones, scripts NSE y límites configurados; los objetivos vacíos, opciones y perfiles desconocidos se rechazan. |
| Flujo de API | El perfil solicitado se conserva al crear el trabajo y queda en la respuesta junto al estado. |
| Puertos y servicios | Solo los puertos abiertos producen eventos; los campos siguen el formato común. |
| NSE con CVE y CVSS | Se genera un evento por CVE único con CVSS y severidad derivados. |
| Hallazgo sin CVE | Se genera `vulnerability_detected` con severidad media. |
| Script a nivel de host | Se genera un hallazgo con puerto, protocolo y servicio nulos. |
| Resultados negativos / error | `NOT VULNERABLE`, `ERROR:` y salida vacía no producen eventos de vulnerabilidad. |
| Nmap sin informe o con código distinto de cero | El trabajo queda `failed`, no se publica al SIEM y se elimina el XML temporal. |
| XML inválido | El trabajo queda `failed` y no se expone como escaneo completado. |
| Informe del Dashboard | Se filtran eventos informativos y los hallazgos se exponen con el tipo normalizado. |

## Comprobación manual opcional

Con el servicio del escáner y un SIEM/mock disponibles, usar un objetivo local autorizado:

```bash
curl -X POST http://localhost:8004/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","profile":"vuln"}'
```

Tomar el `scan_id` de la respuesta y consultar el estado hasta que termine:

```bash
curl http://localhost:8004/scan/<scan_id>
curl http://localhost:8004/scans/<scan_id>/report
```

En un resultado `completed`, comprobar que los eventos de puerto/servicio estén en el estado del escaneo, que los hallazgos estén normalizados según el contrato y que el SIEM reciba el mismo `event_id`. Si no hay hallazgos, se espera una lista vacía en el informe; esto no certifica que el host esté libre de vulnerabilidades.

Los escaneos manuales generan tráfico de red. Ejecutarlos únicamente contra un objetivo autorizado y dentro del entorno de laboratorio.

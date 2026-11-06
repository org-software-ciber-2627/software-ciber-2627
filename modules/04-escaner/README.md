# Módulo 4 · Escáner de vulnerabilidades

Equipo: `equipo-04-escaner`  
Puerto externo: `8004`

API Flask que ejecuta Nmap en segundo plano y permite consultar
los escaneos y sus informes.

El formato completo de las respuestas está en el
[contrato de API](contract/README.md).

## 1. Arrancar con Docker

Requisitos: Docker Desktop iniciado y puerto 8004 disponible.

Desde la raíz del repositorio, donde está `docker-compose.yml`:

```powershell
docker compose up -d --build --wait escaner
```

Comprobar el estado:

```powershell
docker compose ps escaner
```

El contenedor debe aparecer como `healthy`.

Consultar los logs si falla:

```powershell
docker compose logs --tail 80 escaner
```

Para detenerlo:

```powershell
docker compose stop escaner
```

## 2. Comprobar la API

```powershell
Invoke-RestMethod -Uri "http://localhost:8004/health"
```

Respuesta esperada:

```json
{
  "status": "ok",
  "module": "04-escaner"
}
```

Esto comprueba que la API responde, no la disponibilidad del SIEM
ni el funcionamiento de un escaneo.

## 3. Consultar el catálogo

```powershell
(Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8004/scans").Content
```

Devuelve una lista de escaneos ordenados del más reciente al más antiguo:

```json
[
  {
    "scan_id": "scan-001",
    "created_at": "2026-11-06T10:30:00Z",
    "target": "192.0.2.10",
    "profile": "quick",
    "status": "completed"
  }
]
```

Este JSON es un ejemplo simulado. Los identificadores reales se generan
al crear cada escaneo.

Si no hay escaneos, devuelve `200 OK` con `[]`.

El Dashboard obtiene aquí el `scan_id` para consultar el informe.
`GET /events` es un alias del mismo catálogo.

## 4. Crear un escaneo de prueba

Utilizar una IP del laboratorio autorizado que sea accesible desde
el contenedor. Introducirla cuando lo solicite PowerShell:

```powershell
$objetivo = Read-Host "IP del objetivo de laboratorio"
$cuerpo = @{ target = $objetivo; profile = "quick" } | ConvertTo-Json
$escaneo = Invoke-RestMethod -Uri "http://localhost:8004/scan" -Method Post -ContentType "application/json" -Body $cuerpo
$scanId = $escaneo.scan_id
$scanId
```

`POST /scan` devuelve `200` con el trabajo creado. El escaneo continúa
en segundo plano: ese 200 no significa que haya terminado ni que sus
eventos se hayan entregado al SIEM.

Perfiles disponibles:

- `quick`: escaneo TCP básico; puede producir solo eventos informativos.
- `web`: comprobaciones HTTP mediante una selección de scripts NSE.
- `vuln`: detección de servicios y scripts de la categoría NSE `vuln`.

## 5. Consultar el informe

Si acabas de crear el escaneo, utiliza la variable `$scanId` anterior.

Para consultar uno del catálogo, introduce su identificador:

```powershell
$scanId = Read-Host "scan_id obtenido de GET /scans"
```

Consulta:

```powershell
$respuesta = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8004/scans/$scanId/report"
$respuesta.StatusCode
$respuesta.Content
```

La petición no lleva body y no lanza otro escaneo.

| Respuesta | Significado |
|---|---|
| 200 con una lista de hallazgos | Informe disponible. |
| 200 con `[]` | Escaneo terminado sin vulnerabilidades incluidas en el informe. |
| 202 | Escaneo pendiente o ejecutándose; consultar de nuevo más tarde. |
| 404, `SCAN_NOT_FOUND` | El identificador no existe. |
| 500, `SCAN_FAILED` | El escaneo ha fallado. |
| 500, `INTERNAL_ERROR` | No se pudo recuperar el informe. |

Ejemplo de respuesta 202:

```json
{
  "scan_id": "scan-001",
  "estado": "en_curso",
  "mensaje": "El informe todavía no está disponible"
}
```

Ejemplo de error:

```json
{
  "error": {
    "codigo": "SCAN_NOT_FOUND",
    "mensaje": "No existe un escaneo con ese identificador"
  }
}
```

PowerShell puede mostrar los códigos 404 y 500 como errores del comando.
Eso no significa necesariamente que Flask esté apagado: hay que revisar
el código HTTP y el cuerpo devuelto.

El informe contiene una lista directa de vulnerabilidades.
Excluye los eventos informativos `port_open` y `service_detected`.
Por eso un escaneo `quick` puede devolver `[]` aunque detecte puertos.

Los hallazgos se presentan con `source: "scanner"`,
`event_type: "vulnerability_detected"` y el objetivo en `details.target`.
La adaptación no modifica los eventos originales enviados al SIEM.

## 6. Otras consultas

| Ruta | Uso |
|---|---|
| `GET /events` | Alias del catálogo `/scans`. |
| `GET /scan/{scan_id}` | Estado del trabajo y eventos originales, incluidos los informativos. |
| `GET /diff?base={id1}&target={id2}` | Comparación de dos escaneos completados. |

Para `/diff`:

- 400: falta algún identificador.
- 404: algún escaneo no existe.
- 409: algún escaneo está pendiente, ejecutándose o fallido.
- 500: estado desconocido, si no se ha detectado antes un estado que produzca 409.

La comparación usa IP, puerto y título y devuelve `new`, `fixed`
y `unchanged`. `fixed` indica ausencia en el segundo escaneo;
no demuestra por sí solo que una vulnerabilidad se haya corregido.

## 7. Ejecutar los tests

Desde la raíz del repositorio, usando la imagen del escáner:

```powershell
docker compose build escaner
docker compose run --rm --no-deps escaner python -m unittest discover -s . -p "test_*.py" -v
```

Alternativamente, con Python instalado localmente:

```powershell
python -m pip install -r modules/04-escaner/requirements.txt
python -m unittest discover -s modules/04-escaner/src -p "test_*.py" -v
```

Las pruebas cubren el informe, el catálogo, `/health` y `/diff`.
Utilizan datos controlados, sin lanzar escaneos reales ni publicar al SIEM.

Algunas pruebas provocan errores deliberadamente y generan logs `ERROR`.
El resultado final debe ser `OK`.

## 8. Conexión y limitaciones

- Desde el equipo que publica Docker: `http://localhost:8004`.
- Entre servicios de la red Docker: `http://escaner:80`.
- Desde otro ordenador: utilizar la IP accesible del equipo anfitrión
  y el puerto 8004.
- La API actual no comprueba autenticación.
- Los trabajos se guardan en memoria y se pierden al reiniciar el proceso
  o contenedor. Después hay que crear nuevos escaneos.
- Un error o un timeout no equivale a un informe vacío.
- No se sustituyen peticiones reales fallidas por datos simulados.
- Las pruebas unitarias no acreditan la integración real con el Dashboard
  ni el almacenamiento en el SIEM.

El escáner envía eventos al SIEM mediante `POST /events`, un evento por
petición. El destino se configura con `SIEM_URL`; en la red Docker
compartida se utiliza `http://siem:80/events`.

Ese endpoint pertenece al SIEM y es distinto del `GET /events`
del escáner. Consultar un informe no confirma la entrega al SIEM.

# Contrato del módulo 02 · IDS

Versión `1.0.0`. Este contrato define cómo el grupo 1 (Identidad) entrega al IDS
los logs que debe analizar. La fuente de verdad estructurada es
[`openapi.yaml`](./openapi.yaml).

## Entrega de logs desde G1

G1 debe enviar lotes mediante:

```http
POST /logs HTTP/1.1
Host: ids
Content-Type: application/json
Accept: application/json
```

El cuerpo contiene entre 1 y 1000 líneas. Cada línea se entrega sin modificar en
`raw_line`:

```json
{
  "source": "01-identidad",
  "logs": [
    {
      "id": "g1-log-00000001",
      "raw_line": "Mar 27 13:08:09 ip-10-77-20-248 sshd[1361]: Accepted publickey for ubuntu from 85.245.107.41 port 54259 ssh2"
    }
  ]
}
```

`id` debe ser estable para que el IDS pueda ignorar reintentos del mismo lote.
G1 debe enviar las líneas en orden cronológico ascendente. El IDS conservará
`raw_line` y podrá procesarla directamente con `parse_log_line`.

Respuesta correcta:

```json
{
  "status": "accepted",
  "accepted": 1,
  "duplicates": 0
}
```

Respuestas de error:

- `400` si el cuerpo no es válido o alguna línea no contiene `raw_line`.
- `413` si el lote supera 1000 entradas o el tamaño máximo permitido.
- `415` si el `Content-Type` no es `application/json`.

El contrato no permite que G1 envíe contraseñas, tokens JWT, claves privadas ni
secretos en los logs. Si una línea contiene datos sensibles por error, G1 debe
sanearla antes de enviarla.

## Formato que analiza IDS

El parser actual espera una línea con esta estructura:

```text
MMM d HH:mm:ss host service[pid]: message
```

Ejemplo real de los logs:

```text
Mar 27 13:08:09 ip-10-77-20-248 sshd[1361]: Accepted publickey for ubuntu from 85.245.107.41 port 54259 ssh2
```

El IDS reconoce, entre otros, `failed_login`, `successful_login`,
`invalid_user`, `authentication_limit_exceeded` y `connection_closed`. Las
líneas que no coincidan con el prefijo syslog se rechazan como entradas
individuales y no deben detener el procesamiento del resto del lote.

## Publicación hacia SIEM

Este contrato de entrada no sustituye la integración de salida. Cuando una regla
detecte actividad, IDS publicará un evento común en `POST /events` del SIEM,
siguiendo [`modules/05-siem/contract/README.md`](../../05-siem/contract/README.md).

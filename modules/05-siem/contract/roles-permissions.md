# Matriz de permisos por rol · SIEM (HU19)

Corresponde a SEM-141 (HU19 / SEM-35). Completa el [contrato de autenticación con Identidad](identity-auth.md): aquella fija **quién eres** (HU18); esta fija **qué puedes hacer** (HU19).

La identidad (`username` y `role`) la devuelve G1 en `GET /auth/validate`. El SIEM no decodifica el JWT.

Orden de las comprobaciones:

1. Autenticación con G1 (HU18): sin token o con un token rechazado, 401.
2. Permiso de la cuenta o el rol sobre la operación: si no lo tiene, 403 `FORBIDDEN`, **antes de leer el cuerpo**.
3. Validación del evento: si está mal formado, 400, como hasta ahora.
4. Solo en `POST /events`, el `source` frente a la cuenta: si no corresponde, 403 `SOURCE_MISMATCH`, **antes de guardar**.

## Roles y cuentas

| Cuenta | Rol en G1 | Módulo |
| --- | --- | --- |
| `svc-ids` | `servicio` | G2 IDS (productor) |
| `svc-honeypot` | `servicio` | G3 Honeypot (productor) |
| `svc-escaner` | `servicio` | G4 Escáner (productor) |
| `svc-pentesting` | `servicio` | G8 Pentesting (productor) |
| `svc-soar` | `servicio` | G6 SOAR (consumidor) |
| `svc-siem` | `servicio` | G5 SIEM (solo lee su secreto en G1) |
| Usuarios `analista` | `analista` | G7 Dashboard |
| Usuarios `admin` | `admin` | Administración |

## Matriz de permisos

| Operación | Permitido | Resto |
| --- | --- | --- |
| `GET /health` | Todos, sin token | No aplica |
| `POST /events` | `svc-ids`, `svc-honeypot`, `svc-escaner`, `svc-pentesting` | 403 `FORBIDDEN` |
| `GET /events` | `analista`, `admin` | 403 `FORBIDDEN` |
| `GET /alerts` | `svc-soar`, `analista`, `admin` | 403 `FORBIDDEN` |
| `GET /alerts/{id}` | `svc-soar`, `analista`, `admin` | 403 `FORBIDDEN` |

### Correspondencia entre cuenta y `source`

En `POST /events`, cada cuenta productora solo puede publicar su propio origen:

| Cuenta | `source` permitido |
| --- | --- |
| `svc-ids` | `ids` |
| `svc-honeypot` | `honeypot` |
| `svc-escaner` | `scanner` |
| `svc-pentesting` | `pentesting` |

Si el `source` del evento no corresponde a la cuenta, el SIEM responde 403 `SOURCE_MISMATCH` y no inserta el evento ni genera ninguna alerta.

## Decisiones

- **`admin` no publica eventos.** No es un productor; así nadie puede introducir eventos que no vengan de un módulo real.
- **Los productores no leen alertas ni el histórico.** Mínimo privilegio: solo necesitan enviar.
- **`svc-soar` no lee el histórico de eventos.** Solo necesita las alertas.
- **La cuenta genérica `servicio` de G1 v1.3.0 no tiene permisos** en el SIEM: cada módulo usa su cuenta `svc-*` (propuesta A, ratificada con G1 el 20/11/2026).
- **Un rol desconocido se deniega.** Si G1 devuelve un rol que no está en esta matriz, la respuesta es 403.

## Respuestas

| Situación | Respuesta | Código |
| --- | --- | --- |
| Sin token o token inválido | 401 (HU18) | `UNAUTHENTICATED` |
| Token válido, cuenta o rol sin permiso | 403 | `FORBIDDEN` |
| Productor publicando otro `source` | 403 | `SOURCE_MISMATCH` |

```json
{ "error": { "code": "FORBIDDEN", "message": "This account is not allowed to perform this operation" } }
```

```json
{ "error": { "code": "SOURCE_MISMATCH", "message": "The event source does not match the authenticated account" } }
```

Ante un 403, el cliente registra el fallo y **no reintenta**: repetir la petición no cambia el resultado.

## Criterios verificables (SEM-143)

| Caso | Resultado |
| --- | --- |
| `svc-ids` envía un evento con `source: ids` | 200 |
| `svc-ids` envía un evento con `source: honeypot` | 403 `SOURCE_MISMATCH`, sin inserción |
| `svc-soar` o `admin` envían un evento | 403 `FORBIDDEN`, sin inserción |
| `analista` consulta `GET /events` | 200 |
| `svc-soar` consulta `GET /events` | 403 `FORBIDDEN` |
| `svc-soar` consulta `GET /alerts` y `GET /alerts/{id}` | 200 |
| `svc-honeypot` consulta `GET /alerts` | 403 `FORBIDDEN` |
| Rol desconocido en cualquier operación protegida | 403 `FORBIDDEN` |
| `GET /health` sin token | 200 |

## Estado

Propuesta de G5 el 24/11/2026. G1 confirmado: `GET /auth/validate` devuelve `valid`, `user_id`, `username` y `role`, y el SIEM exige `username` y `role` (si faltan, 503). G7 confirmó los permisos del analista en su revisión. Pendiente de confirmar con G6 (uso de `svc-soar`). La implementación corresponde a SEM-142 y las pruebas a SEM-143.
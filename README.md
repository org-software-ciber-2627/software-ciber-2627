# Ciberurjc

Monorepo compartido de la asignatura Ingeniería del Software (3º Grado en Ciberseguridad, URJC). 8 equipos construyen una única herramienta integrada, tipo "mini-SOC": cada equipo es dueño de un módulo, y todos comparten la misma infraestructura de despliegue (`docker-compose.yml`) y el mismo pipeline de CI.

## Módulos

| # | Carpeta | Módulo | Equipo | Puerto |
|---|---|---|---|---|
| 1 | `modules/01-identidad` | Identidad y secretos | `equipo-01-identidad` | 8001 |
| 2 | `modules/02-ids` | IDS/NIDS | `equipo-02-ids` | 8002 |
| 3 | `modules/03-honeypot` | Honeypot | `equipo-03-honeypot` | 8003 |
| 4 | `modules/04-escaner` | Escáner de vulnerabilidades | `equipo-04-escaner` | 8004 |
| 5 | `modules/05-siem` | SIEM | `equipo-05-siem` | 8005 |
| 6 | `modules/06-soar` | SOAR | `equipo-06-soar` | 8006 |
| 7 | `modules/07-dashboard` | Panel de control (Dashboard) | `equipo-07-dashboard` | 8007 |
| 8 | `modules/08-pentesting` | Pentesting externo | `equipo-08-pentesting` | 8008 |

## Cómo arrancarlo

```bash
cp .env.example .env
docker compose up --build
```

Cada módulo responde en `http://localhost:80NN/health` con `{"status":"ok","module":"NN-nombre"}`.

## Flujo de trabajo

1. Cada equipo trabaja en su propia rama (`equipo-NN-nombre`).
2. Los cambios llegan a `main` solo mediante **Pull Request**.
3. El CI (`build-and-health` y `event-schema`) debe estar en verde.
4. La revisión es cruzada y rotatoria, en anillo: el equipo N revisa los PRs del equipo N+1, y el equipo 8 revisa los del equipo 1 (ver `.github/CODEOWNERS`).
5. Con al menos una aprobación y CI verde, se fusiona a `main`.

El equipo de Dashboard (`equipo-07-dashboard`) mantiene el CI y la infraestructura compartida (este `docker-compose.yml` y `.github/`), pero **no aprueba ni bloquea el trabajo de los demás equipos**.

## Cómo sustituir vuestro placeholder por el servicio real

Cada módulo arranca hoy como un contenedor `nginx:alpine` mínimo que solo responde en `/health`. Para sustituirlo:

1. Reemplazad el `Dockerfile` de vuestra carpeta (`modules/NN-nombre/Dockerfile`) por el de vuestra aplicación real.
2. Mantened el mismo puerto interno (80) y el endpoint `GET /health` respondiendo `200` — el CI y el docker-compose dependen de ello.
3. Publicad el contrato de vuestra API en `modules/NN-nombre/contract/` antes de programar la lógica interna.
4. Construid mocks de las dependencias que todavía no existan, en `modules/NN-nombre/mocks/`.

## Convención de nombres

Las claves de Jira van en el nombre de rama y en los mensajes de commit, por ejemplo:

```
git checkout -b equipo-07-dashboard/DSH-12-vista-alertas
git commit -m "feat: vista de alertas (DSH-12)"
```

## Recursos compartidos

- `shared/event-schema.json`: esquema común de evento de seguridad (placeholder hasta el acuerdo en la sesión conjunta de arranque).
- `shared/auth-contract.md`: contrato de autenticación (lo publica Identidad).

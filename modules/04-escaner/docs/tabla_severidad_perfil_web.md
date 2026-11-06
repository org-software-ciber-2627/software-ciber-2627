# E4EDV-41 · Tabla de severidad del perfil web

**Historia:** E4EDV-17 – Perfil de comprobaciones web básicas
**Código:** `severity.py` (tabla + detectores) y `parser.py` (la usa)

## Criterio

Se usa la escala común del SIEM (`critical`, `high`, `medium`, `low`):

- **critical**: ejecución remota de código sin autenticación.
- **high**: permite modificar el servidor o filtra código o secretos.
- **medium**: debilidad de configuración explotable junto con otro fallo (XSS, robo de sesión, clickjacking…).
- **low**: endurecimiento recomendado o fuga de información menor.

Si un script devuelve una puntuación CVSS, manda el CVSS (lógica anterior del parser). La tabla solo se aplica cuando no hay CVSS.

## Tabla

| Script NSE | Hallazgo | Severidad | OWASP 2021 |
|---|---|---|---|
| http-vuln-cve2017-5638 | Apache Struts RCE | critical | A06 |
| http-vuln-cve2015-1635 | HTTP.sys RCE (MS15-034) | critical | A06 |
| http-shellshock | Shellshock en CGI | critical | A06 |
| http-vuln-cve2011-3192 | Apache byterange DoS | high | A06 |
| http-git | Repositorio .git expuesto | high | A01 |
| http-methods | PUT / DELETE habilitados | high | A05 |
| http-enum | Ruta sensible accesible (1 evento por ruta) | medium | A01 |
| http-trace | TRACE habilitado | medium | A05 |
| http-cors | CORS permisivo | medium | A05 |
| http-cookie-flags | Cookie sin HttpOnly (1 evento por cookie) | medium | A05 |
| http-cookie-flags | Cookie sin Secure en HTTPS | medium | A05 |
| http-security-headers | Falta Strict-Transport-Security (solo HTTPS) | medium | A05 |
| http-security-headers | Falta Content-Security-Policy | medium | A05 |
| http-slowloris-check | Vulnerable a Slowloris | medium | A05 |
| http-security-headers | Falta X-Frame-Options | low | A05 |
| http-security-headers | Falta X-Content-Type-Options | low | A05 |
| http-methods | Otros métodos peligrosos (p. ej. OPTIONS) | low | A05 |
| http-internal-ip-disclosure | Fuga de IP interna | low | A05 |
| http-title, http-server-header | Inventario | sin evento | — |

## Decisiones

- **Un evento por hallazgo concreto** (por cookie, por ruta, por cabecera). Así `/diff` puede detectar qué se ha corregido entre dos escaneos.
- **TRACE no se duplica**: si `http-methods` solo encuentra TRACE, no genera evento porque ya lo reporta `http-trace`.
- **Cabeceras ausentes**: `http-security-headers` solo lista las cabeceras presentes, y si no hay ninguna no deja salida. Por eso, si en un puerto se ejecutó `http-title` y no aparece `http-security-headers`, se consideran ausentes todas.
- Los eventos llevan un campo nuevo, `details.owasp`, para que el Dashboard pueda agrupar por categoría.

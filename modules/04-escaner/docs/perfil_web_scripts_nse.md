# E4EDV-39 · Selección de scripts NSE del perfil web

**Historia:** E4EDV-17 – Perfil de comprobaciones web básicas (`--script http-*`)
**Módulo:** 4 · Escáner de vulnerabilidades (Grupo 4)
**Estado:** Listo → siguiente subtarea: E4EDV-40 (añadir el perfil al orquestador)

## 1. Por qué no usamos `http-*` tal cual

El perfil `web` actual de `runner.py` lanza `--script http-*`, que en Nmap 7.9x son **más de 130 scripts**. Problemas:

| Problema | Ejemplos dentro de `http-*` | Impacto |
|---|---|---|
| Fuerza bruta | `http-brute`, `http-form-brute`, `http-wordpress-brute`, `http-proxy-brute`, `http-iis-short-name-brute` | Bloqueos de cuentas en Identidad y ruido en el Honeypot/IDS de otros grupos |
| Denegación de servicio | `http-slowloris` | Puede tumbar los contenedores de los compañeros |
| Fuzzing / explotación | `http-form-fuzzer`, `http-fileupload-exploiter`, `http-put`, `http-sql-injection` | Lento, con falsos positivos; además el pentesting web lo cubre el Módulo 8 (ZAP) |
| Envían datos a terceros | `http-xssed`, `http-google-malware`, `http-virustotal`, `http-robtex-*` | Sacan IPs/URLs del laboratorio a servicios externos |
| Específicos de productos que no usamos | `http-wordpress-*`, `http-drupal-*`, `http-domino-*`, `http-vuln-wnr1000-creds`, `http-huawei-*` | Solo añaden tiempo de escaneo |

Conclusión: el perfil web debe usar una **lista explícita** de scripts seguros y útiles para un "mini-SOC", no el comodín.

## 2. Criterios de selección

1. **No destructivo**: se excluyen las categorías `brute`, `dos` y los `exploit` que modifican el objetivo.
2. **Sin dependencias externas**: nada que consulte APIs de terceros.
3. **Relevante para OWASP Top 10** (A05 Configuración insegura, A06 Componentes vulnerables, A01 Control de acceso).
4. **Genérico**: aplicable a las APIs Flask/Node/etc. del resto de módulos de Ciberurjc.
5. **Tiempo acotado**: el escaneo web completo de un host debe quedar en pocos minutos.

## 3. Scripts seleccionados

### 3.1 Vulnerabilidades conocidas (CVE) — devuelven `VULNERABLE`, el parser actual ya los detecta

| Script | Qué comprueba | OWASP |
|---|---|---|
| `http-vuln-cve2017-5638` | RCE en Apache Struts (Content-Type) | A06 |
| `http-vuln-cve2015-1635` | MS15-034, RCE en HTTP.sys (IIS) | A06 |
| `http-vuln-cve2011-3192` | Apache byterange (DoS), solo comprobación | A06 |
| `http-slowloris-check` | Si el servidor es vulnerable a Slowloris (no lanza el ataque) | A05 |
| `http-shellshock` | Shellshock en CGI (inyecta un `echo` inofensivo) | A06 |

### 3.2 Configuración insegura — **no** devuelven `VULNERABLE`, necesitan regla propia (ver E4EDV-41)

| Script | Hallazgo típico | OWASP |
|---|---|---|
| `http-security-headers` | Faltan HSTS, X-Frame-Options, CSP, X-Content-Type-Options | A05 |
| `http-cookie-flags` | Cookies de sesión sin `HttpOnly` / `Secure` | A05 |
| `http-methods` | Métodos peligrosos habilitados (PUT, DELETE, TRACE) | A05 |
| `http-trace` | TRACE habilitado (Cross-Site Tracing) | A05 |
| `http-cors` | CORS permisivo (`Access-Control-Allow-Origin: *`) | A05 |
| `http-internal-ip-disclosure` | Fuga de IP interna en cabeceras | A05 |
| `http-git` | Repositorio `.git/` expuesto (fuga de código y secretos) | A01 |
| `http-enum` | Rutas sensibles: paneles admin, backups, ficheros de configuración | A01 |

### 3.3 Inventario (no generan eventos, sirven de contexto en `details`)

| Script | Uso |
|---|---|
| `http-title` | Identificar qué módulo de Ciberurjc responde |
| `http-server-header` | Versión de servidor (complementa `-sV`) |

### 3.4 Descartados explícitamente (justificación para la Review)

- `http-sql-injection`, `http-dombased-xss`, `http-stored-xss`, `http-csrf`: intrusivos y con muchos falsos positivos; los cubre el Módulo 8 con ZAP.
- `http-default-accounts`: prueba credenciales por defecto → mismo riesgo de bloqueo que la fuerza bruta. Se podría añadir más adelante con acuerdo del equipo de Identidad en el SoS.
- `http-headers`, `http-comments-displayer`, `http-errors`: salida muy ruidosa y sin valor como hallazgo.

## 4. Valor final para E4EDV-40

Cadena lista para usar en `PROFILES["web"]`:

```python
WEB_SCRIPTS = ",".join([
    # CVE conocidas
    "http-vuln-cve2017-5638", "http-vuln-cve2015-1635", "http-vuln-cve2011-3192",
    "http-slowloris-check", "http-shellshock",
    # Configuración insegura
    "http-security-headers", "http-cookie-flags", "http-methods", "http-trace",
    "http-cors", "http-internal-ip-disclosure", "http-git", "http-enum",
    # Inventario
    "http-title", "http-server-header",
])
```

Puertos: `80,443,8080,8443` + los puertos de los módulos de Ciberurjc (p. ej. `8000-8010`, a confirmar en el docker-compose del equipo de Dashboard).

## 5. Criterios de aceptación de esta subtarea

- [x] Lista explícita de scripts con justificación por cada uno.
- [x] Excluidos los scripts `brute`, `dos`, intrusivos y con llamadas externas.
- [x] Cada script mapeado a una categoría OWASP para la tabla de severidad (E4EDV-41).
- [x] Identificados los scripts que el parser actual **no** convierte en evento (sección 3.2).

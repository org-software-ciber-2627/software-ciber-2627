# =============================================================================
# PRUEBA CONJUNTA DEL DASHBOARD (Windows, PowerShell 5.1 o superior)
# Equivale a probar.sh.
#
# Que hace, en resumen:
#   1. Comprueba que Docker esta disponible.
#   2. Arranca el Dashboard con docker compose (junto con los modulos de los que depende).
#   3. Si ya estan en la rama, arranca tambien los mocks de SOAR y Escaner.
#   4. Espera a que respondan y lanza una serie de comprobaciones (OK / FALLO).
#   5. Al terminar para y borra todo lo que ha arrancado, aunque algo falle.
#
# Garantias: no modifica tu .env, no cambia de rama y no sube nada a GitHub.
#
# NOTA: el texto va sin tildes a proposito. PowerShell 5.1 lee mal los .ps1 sin BOM que
# contienen caracteres no ASCII.
#
# Requisitos: Docker Desktop abierto.
# Uso (desde cualquier carpeta del clon):
#   powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1
# =============================================================================

# 'Continue' a proposito: si una comprobacion falla queremos seguir y ver TODOS los fallos.
$ErrorActionPreference = 'Continue'

# --- Rutas y nombres -----------------------------------------------------------
# $Raiz = raiz del clon, calculada a partir de la ubicacion del script (sirve lance donde se lance).
$Raiz = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$Mod  = Join-Path $Raiz 'modules\07-dashboard'
# Nombre del "proyecto" de compose: aisla esta prueba de cualquier otro docker compose del equipo.
$Proj = 'dashprueba'
# Copia temporal del .env.example para no tocar el .env real del usuario.
$EnvF = Join-Path ([System.IO.Path]::GetTempPath()) ('probar-dashboard-' + [guid]::NewGuid().ToString('N') + '.env')
# $Fallo pasa a $true si cualquier comprobacion falla; es el codigo de salida final del script.
$script:Fallo = $false

# --- Funciones de salida con color ------------------------------------------------
function Ok($m)   { Write-Host "  OK    $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  FALLO $m" -ForegroundColor Red; $script:Fallo = $true }
function Step($m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }

# --- Utilidades de comprobacion ----------------------------------------------------------
# Get-Text URL -> cuerpo de la respuesta, o cadena vacia si falla la peticion.
function Get-Text($url) {
    try { return (Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 5).Content } catch { return '' }
}
# Test-Url URL -> $true si la URL responde con exito (codigo 2xx).
function Test-Url($url) {
    try { $null = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 3; return $true } catch { return $false }
}
# Get-Code URL -> codigo HTTP de la respuesta (200, 404...). 0 si no hay conexion.
function Get-Code($url) {
    try { return [int](Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 3).StatusCode }
    catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}
# Count-Key URL CLAVE -> cuantas veces aparece "CLAVE": en el JSON de la URL.
# Sirve para contar elementos (p. ej. cuantas alertas hay) sin parsear el JSON.
function Count-Key($url, $key) {
    $t = Get-Text $url
    return ([regex]::Matches($t, '"' + [regex]::Escape($key) + '"\s*:')).Count
}

# try/finally: el bloque finally se ejecuta SIEMPRE al salir (exito, fallo o Ctrl+C) para no
# dejar contenedores ni redes colgando que ocupen los puertos en la siguiente prueba.
try {
    # --- 1. Requisitos ----------------------------------------------------------
    Step 'Requisitos'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host 'Falta docker (instala Docker Desktop).'; exit 1
    }
    docker compose version *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host "Falta 'docker compose' (v2)."; exit 1 }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host 'Docker no responde (abre Docker Desktop y espera a que arranque).'; exit 1 }
    Ok 'docker y compose disponibles'

    # --- 2. Variables de entorno ------------------------------------------------
    # docker compose lee las URLs de los modulos de un fichero de variables. Partimos de .env.example.
    Copy-Item (Join-Path $Raiz '.env.example') $EnvF

    # --- 3. Arranque del Dashboard ----------------------------------------------
    # "up --build -d dashboard": construye la imagen y arranca el dashboard en segundo plano.
    # Por el depends_on del docker-compose tambien arranca identidad, escaner, siem y soar.
    Step 'Arrancando el Dashboard (docker compose)'
    Push-Location $Raiz
    docker compose --env-file $EnvF -p $Proj up --build -d dashboard
    $codigo = $LASTEXITCODE
    Pop-Location
    if ($codigo -ne 0) { Write-Host 'docker compose fallo (puertos 8001-8007 ocupados?).'; exit 1 }

    # --- 4. Mocks de SOAR y Escaner (solo si ya estan en la rama) ---------------
    # Los mocks son servicios Flask con datos fijos. Cuando los ficheros existen se construyen y se
    # arrancan aparte, en los puertos 5001 (SOAR) y 5002 (Escaner). Si no existen se omiten sin error.
    $HayMocks = (Test-Path (Join-Path $Mod 'mocks\mock_SOAR\app.py')) -and (Test-Path (Join-Path $Mod 'mocks\mock_scanner\app.py'))
    if ($HayMocks) {
        Step 'Arrancando los mocks de SOAR y Escaner'
        docker build -q -t mock-soar (Join-Path $Mod 'mocks\mock_SOAR') | Out-Null
        if ($LASTEXITCODE -eq 0) { docker run -d --rm --name mock-soar -p 5001:5001 mock-soar | Out-Null }
        if ($LASTEXITCODE -ne 0) { Bad 'el mock SOAR no arranca' }
        docker build -q -t mock-scanner (Join-Path $Mod 'mocks\mock_scanner') | Out-Null
        if ($LASTEXITCODE -eq 0) { docker run -d --rm --name mock-scanner -p 5002:5002 mock-scanner | Out-Null }
        if ($LASTEXITCODE -ne 0) { Bad 'el mock Escaner no arranca' }
    }

    # --- 5. Espera activa -------------------------------------------------------
    # Que el contenedor este "arrancado" no significa que ya responda. Se sondea /health cada 2 s
    # hasta 30 veces (60 s maximo) antes de empezar a comprobar.
    Step 'Esperando a que respondan (max. 60 s)'
    $urls = @('http://localhost:8007/health')
    if ($HayMocks) { $urls += @('http://localhost:5001/health', 'http://localhost:5002/health') }
    foreach ($u in $urls) {
        for ($i = 0; $i -lt 30; $i++) {
            if (Test-Url $u) { break }
            Start-Sleep -Seconds 2
        }
    }

    # --- 6. Comprobaciones ------------------------------------------------------
    Step 'Comprobaciones'

    # Dashboard: salud y contenido servido por nginx.
    if ((Get-Text 'http://localhost:8007/health') -match '"ok"') { Ok 'dashboard: /health responde 200 (lo que exige el CI)' } else { Bad 'dashboard: /health' }
    if ((Get-Text 'http://localhost:8007/') -match 'Dashboard Principal') { Ok 'dashboard: la pagina principal se sirve' } else { Bad 'dashboard: pagina principal' }

    # Login (maqueta): la pagina existe y la principal esta protegida y tiene boton de cierre de sesion.
    # OJO: es una maqueta, no consulta a Identidad; aqui solo se comprueba que los ficheros estan.
    if ((Get-Text 'http://localhost:8007/login.html') -match 'Acceso CiberURJC') { Ok 'login: login.html se sirve' } else { Bad 'login: falta login.html' }
    $principal = Get-Text 'http://localhost:8007/'
    if (($principal -match 'login\.html') -and ($principal -match 'logout')) {
        Ok 'login: la pagina principal redirige al login si no hay sesion y tiene cierre de sesion'
    } else {
        Bad 'login: la pagina principal no tiene la proteccion o el boton de cerrar sesion'
    }

    # Historias DASHG7-22 y DASHG7-25: datos del mock del SIEM y refresco con hora de actualizacion.
    $n = Count-Key 'http://localhost:8007/mocks/siem-alerts.json' 'alert_id'
    if ($n -eq 4) { Ok 'dashboard: el mock del SIEM tiene 4 alertas' } else { Bad "dashboard: el mock del SIEM devuelve $n alertas (esperaba 4)" }
    if ((Get-Text 'http://localhost:8007/SIEM-alert.js') -match 'hora-actualizacion') { Ok 'dashboard: el JS actualiza la hora de ultima actualizacion' } else { Bad 'dashboard: falta la actualizacion de la hora' }

    # Higiene: el Dockerfile solo debe publicar el mock del SIEM, no el codigo de los mocks de Python.
    if ((Get-Code 'http://localhost:8007/mocks/mock_SOAR/app.py') -eq 404) {
        Ok 'dashboard: el codigo de los mocks de Python no se publica en la web'
    } else {
        Bad 'dashboard: /mocks/mock_SOAR/app.py es accesible desde la web (revisar el Dockerfile)'
    }

    # Mocks de SOAR y Escaner (solo si estan en la rama): salud y numero de elementos.
    if ($HayMocks) {
        if ((Get-Text 'http://localhost:5001/health') -match '"ok"') { Ok 'mock SOAR: /health responde' } else { Bad 'mock SOAR: /health' }
        $n = Count-Key 'http://localhost:5001/incidents' 'id'
        if ($n -eq 3) { Ok 'mock SOAR: GET /incidents devuelve 3 incidentes' } else { Bad "mock SOAR: /incidents devuelve $n (esperaba 3)" }
        if ((Get-Text 'http://localhost:5002/health') -match '"ok"') { Ok 'mock Escaner: /health responde' } else { Bad 'mock Escaner: /health' }
        $n = Count-Key 'http://localhost:5002/findings' 'id'
        if ($n -eq 3) { Ok 'mock Escaner: GET /findings devuelve 3 hallazgos' } else { Bad "mock Escaner: /findings devuelve $n (esperaba 3)" }
    } else {
        Write-Host '  (mocks de SOAR y Escaner: aun no estan en esta rama; se omiten)'
    }

    # --- 7. Resultado y prueba visual -------------------------------------------
    Write-Host ''
    if (-not $script:Fallo) { Write-Host 'TODO CORRECTO' -ForegroundColor Green } else { Write-Host 'HAY FALLOS (arriba)' -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Prueba visual: abre http://localhost:8007. Te lleva al login: entra con cualquier usuario y contrasena.'
    Write-Host "Despues deberias ver 4 alertas ordenadas por severidad, la hora real en 'Ultima actualizacion'"
    Write-Host "(cambia sola cada 30 s) y el boton 'Cerrar Sesion', que te devuelve al login."
    # Si el script se lanza en una terminal interactiva, espera a que pulses Enter para dejarte mirar
    # el navegador antes de limpiar. Si no hay terminal (CI, redirecciones), limpia directamente.
    if (-not [Console]::IsInputRedirected) { Read-Host 'Pulsa Enter para parar todo y limpiar' | Out-Null }
    exit ([int]$script:Fallo)
}
finally {
    # --- Limpieza (siempre) ------------------------------------------------------
    Step 'Limpiando'
    docker rm -f mock-soar mock-scanner *> $null
    Push-Location $Raiz
    docker compose --env-file $EnvF -p $Proj down *> $null
    Pop-Location
    Remove-Item $EnvF -ErrorAction SilentlyContinue
    Write-Host '  hecho'
}

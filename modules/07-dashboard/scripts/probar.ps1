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
#   powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1 [opciones]
#
# Opciones (ver "probar.ps1 -h"):
#   -s  no reconstruir las imagenes (demo rapida)      -m  dejar todo levantado al terminar
#   -c  solo comprobar lo que ya esta corriendo        -p  parar lo que dejo -m
#   -n  sin los mocks de SOAR y Escaner                -h  ayuda
# =============================================================================

# Opciones. Cada una es un "switch" (presente = activada). Los alias permiten la forma corta:
# -s equivale a -SinBuild, -m a -Mantener, etc. Una opcion desconocida la rechaza PowerShell.
param(
    [Alias('s')][switch]$SinBuild,
    [Alias('m')][switch]$Mantener,
    [Alias('c')][switch]$SoloComprobar,
    [Alias('p')][switch]$Parar,
    [Alias('n')][switch]$SinMocks,
    [Alias('h')][switch]$Ayuda
)

# --- Ayuda ----------------------------------------------------------------------------------
function Show-Uso {
    @'
Uso: powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1 [opciones]

Sin opciones: construye (con la cache de Docker), arranca, comprueba y limpia al terminar.

  -s, -SinBuild        No reconstruye: usa las imagenes que ya existen (solo construye las que falten).
                       Aviso: tras un "git pull" con cambios, ejecuta antes SIN opciones; si no, puedes
                       probar una imagen antigua y obtener un OK que no corresponde.
  -m, -Mantener        Al terminar no para nada: deja todo levantado y no espera a Enter.
  -c, -SoloComprobar   No arranca ni construye nada: solo ejecuta las comprobaciones sobre lo que ya
                       este corriendo (arrancalo antes con -m, o sin opciones en otra terminal).
  -p, -Parar           Para y borra lo que dejo -m (contenedores, red y mocks). No hace pruebas.
  -n, -SinMocks        No arranca ni comprueba los mocks de SOAR y Escaner.
  -h, -Ayuda           Muestra esta ayuda.

Las opciones se escriben por separado (-s -m).

Flujo recomendado para la demo:
  1) Un rato antes, una vez:    probar.ps1            (construye y deja las imagenes guardadas)
  2) En la demo:                probar.ps1 -s         (no reconstruye; arranca, comprueba y espera)
  3) Si lo quieres ya levantado: probar.ps1 -s -m     y luego  probar.ps1 -c   y al final  probar.ps1 -p
'@
}
if ($Ayuda) { Show-Uso; exit 0 }

# 'Continue' a proposito: si una comprobacion falla queremos seguir y ver TODOS los fallos.
$ErrorActionPreference = 'Continue'

# --- Rutas y nombres -----------------------------------------------------------
# $Raiz = raiz del clon, calculada a partir de la ubicacion del script (sirve lance donde se lance).
$Raiz = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$Mod  = Join-Path $Raiz 'modules\07-dashboard'
# Nombre del "proyecto" de compose: aisla esta prueba de cualquier otro docker compose del equipo
# y hace que las imagenes se llamen siempre igual (dashprueba-*), de modo que -s las reutilice.
$Proj = 'dashprueba'
# Copia temporal del .env.example para no tocar el .env real del usuario.
$EnvF = Join-Path ([System.IO.Path]::GetTempPath()) ('probar-dashboard-' + [guid]::NewGuid().ToString('N') + '.env')
# $Fallo pasa a $true si cualquier comprobacion falla; es el codigo de salida final del script.
$script:Fallo = $false
# Arrancado = $true si ESTA ejecucion ha levantado contenedores. Limpiar = $true si hay que pararlos
# al salir. Asi nunca se tira abajo algo que otra ejecucion (por ejemplo con -m) dejo levantado.
$script:Arrancado = $false
$script:Limpiar = -not ($Mantener -or $SoloComprobar)

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

# --- Utilidades de Docker -----------------------------------------------------------------
# Stop-Prueba -> para y borra los mocks y el proyecto de compose (las imagenes se conservan).
function Stop-Prueba {
    docker rm -f mock-soar mock-scanner *> $null
    Push-Location $Raiz
    docker compose --env-file $EnvF -p $Proj down *> $null
    Pop-Location
}
# Start-Mock NOMBRE IMAGEN CARPETA PUERTO -> construye (salvo con -s y si la imagen ya existe) y
# arranca un mock en su puerto. Si ya esta corriendo, lo reutiliza. Devuelve $true si queda en marcha.
function Start-Mock($nombre, $imagen, $dir, $puerto) {
    $corriendo = docker ps --format '{{.Names}}' | Where-Object { $_ -eq $nombre }
    if ($corriendo) { Write-Host "  $nombre ya esta en marcha; se reutiliza"; return $true }
    docker rm -f $nombre *> $null
    $construir = $true
    if ($SinBuild) {
        docker image inspect $imagen *> $null
        if ($LASTEXITCODE -eq 0) { $construir = $false }
    }
    if ($construir) {
        docker build -q -t $imagen $dir | Out-Null
        if ($LASTEXITCODE -ne 0) { return $false }
    }
    docker run -d --rm --name $nombre -p "${puerto}:${puerto}" $imagen | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# try/finally: el bloque finally se ejecuta SIEMPRE al salir (exito, fallo o Ctrl+C) para no
# dejar contenedores ni redes colgando que ocupen los puertos en la siguiente prueba.
try {
    # --- 1. Requisitos ----------------------------------------------------------
    # Con -c no se usa Docker, asi que no se exige. En el resto de modos si.
    Step 'Requisitos'
    if (-not $SoloComprobar) {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            Write-Host 'Falta docker (instala Docker Desktop).'; exit 1
        }
        docker compose version *> $null
        if ($LASTEXITCODE -ne 0) { Write-Host "Falta 'docker compose' (v2)."; exit 1 }
        docker info *> $null
        if ($LASTEXITCODE -ne 0) { Write-Host 'Docker no responde (abre Docker Desktop y espera a que arranque).'; exit 1 }
        Ok 'docker y compose disponibles'
    } else {
        Ok 'modo solo-comprobar: no se usa Docker'
    }

    # --- 2. Variables de entorno ------------------------------------------------
    # docker compose lee las URLs de los modulos de un fichero de variables. Partimos de .env.example.
    Copy-Item (Join-Path $Raiz '.env.example') $EnvF

    # --- Modo -p: parar lo que dejo -m y salir ----------------------------------
    if ($Parar) {
        Step 'Parando lo que dejo -m'
        Stop-Prueba
        Write-Host '  hecho (contenedores, red y mocks eliminados; las imagenes se conservan)'
        exit 0
    }

    # --- Hay mocks que probar? --------------------------------------------------
    # Los mocks de SOAR y Escaner (servicios Flask con datos fijos) solo se prueban si sus ficheros
    # estan en la rama y no se pidio -n.
    $HayMocks = (-not $SinMocks) -and (Test-Path (Join-Path $Mod 'mocks\mock_SOAR\app.py')) -and (Test-Path (Join-Path $Mod 'mocks\mock_scanner\app.py'))

    if (-not $SoloComprobar) {
        # --- 3. Arranque (se salta con -c) --------------------------------------
        # Proteccion: si ya hay una prueba levantada (por ejemplo con -m), no se arranca otra encima
        # porque los puertos chocarian; se indica que hacer.
        Push-Location $Raiz
        $ya = docker compose --env-file $EnvF -p $Proj ps -q dashboard 2>$null
        Pop-Location
        if ($ya) {
            Write-Host "Ya hay una prueba en marcha (proyecto $Proj)."
            Write-Host 'Usa -c para solo comprobar lo que hay, o -p para pararla antes de volver a arrancar.'
            exit 1
        }

        # "up -d dashboard" arranca el dashboard en segundo plano; por su depends_on arrastra tambien
        # identidad, escaner, siem y soar. Con --build reconstruye las imagenes (usando la cache de
        # Docker); con -s se omite y solo se construyen las que no existan todavia.
        $buildArgs = @()
        if (-not $SinBuild) { $buildArgs = @('--build') }
        if ($SinBuild) { Step 'Arrancando el Dashboard (docker compose, sin reconstruir)' } else { Step 'Arrancando el Dashboard (docker compose)' }
        $script:Arrancado = $true
        Push-Location $Raiz
        docker compose --env-file $EnvF -p $Proj up @buildArgs -d dashboard
        $codigo = $LASTEXITCODE
        Pop-Location
        if ($codigo -ne 0) {
            Write-Host 'docker compose fallo (puertos 8001-8007 ocupados?).'
            $script:Limpiar = $true   # aunque se pidiera -m, si el arranque falla no dejamos restos a medias
            exit 1
        }

        # Mocks: se arrancan aparte, en los puertos 5001 (SOAR) y 5002 (Escaner).
        if ($HayMocks) {
            Step 'Arrancando los mocks de SOAR y Escaner'
            if (-not (Start-Mock 'mock-soar' 'mock-soar' (Join-Path $Mod 'mocks\mock_SOAR') 5001)) { Bad 'el mock SOAR no arranca' }
            if (-not (Start-Mock 'mock-scanner' 'mock-scanner' (Join-Path $Mod 'mocks\mock_scanner') 5002)) { Bad 'el mock Escaner no arranca' }
        }

        # --- 4. Espera activa ---------------------------------------------------
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
    } else {
        # Con -c no se arranca nada: si el Dashboard no responde, se avisa en lugar de dar fallos en cadena.
        if (-not (Test-Url 'http://localhost:8007/health')) {
            Write-Host 'El Dashboard no responde en localhost:8007. Arrancalo antes (sin -c, o con -m) y vuelve a probar.'
            exit 1
        }
    }

    # --- 5. Comprobaciones ------------------------------------------------------
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

    # Mocks de SOAR y Escaner (solo si estan en la rama y no se pidio -n): salud y numero de elementos.
    if ($HayMocks) {
        if ((Get-Text 'http://localhost:5001/health') -match '"ok"') { Ok 'mock SOAR: /health responde' } else { Bad 'mock SOAR: /health' }
        $n = Count-Key 'http://localhost:5001/incidents' 'id'
        if ($n -eq 3) { Ok 'mock SOAR: GET /incidents devuelve 3 incidentes' } else { Bad "mock SOAR: /incidents devuelve $n (esperaba 3)" }
        if ((Get-Text 'http://localhost:5002/health') -match '"ok"') { Ok 'mock Escaner: /health responde' } else { Bad 'mock Escaner: /health' }
        $n = Count-Key 'http://localhost:5002/findings' 'id'
        if ($n -eq 3) { Ok 'mock Escaner: GET /findings devuelve 3 hallazgos' } else { Bad "mock Escaner: /findings devuelve $n (esperaba 3)" }
    } elseif ($SinMocks) {
        Write-Host '  (mocks de SOAR y Escaner: omitidos por -n)'
    } else {
        Write-Host '  (mocks de SOAR y Escaner: no estan en esta rama; se omiten)'
    }

    # --- 6. Resultado y prueba visual -------------------------------------------
    Write-Host ''
    if (-not $script:Fallo) { Write-Host 'TODO CORRECTO' -ForegroundColor Green } else { Write-Host 'HAY FALLOS (arriba)' -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Prueba visual: abre http://localhost:8007. Te lleva al login: entra con cualquier usuario y contrasena.'
    Write-Host "Despues deberias ver 4 alertas ordenadas por severidad, la hora real en 'Ultima actualizacion'"
    Write-Host "(cambia sola cada 30 s) y el boton 'Cerrar Sesion', que te devuelve al login."
    # Solo se pausa si el script arranco el mismo los contenedores y los va a limpiar: asi puedes mirar
    # el navegador antes de que se paren. Con -m o -c no hay nada que limpiar, asi que no se espera.
    # Si no hay terminal interactiva (CI, redirecciones) tampoco se espera.
    if ($script:Limpiar -and $script:Arrancado -and -not [Console]::IsInputRedirected) { Read-Host 'Pulsa Enter para parar todo y limpiar' | Out-Null }
    exit ([int]$script:Fallo)
}
finally {
    # --- Limpieza (solo de lo que arranco esta ejecucion y solo si no se pidio -m) -------------
    if ($script:Arrancado -and $script:Limpiar) {
        Step 'Limpiando'
        Stop-Prueba
        Write-Host '  hecho'
    } elseif ($script:Arrancado) {
        Write-Host ''
        Write-Host 'Todo sigue levantado (-m). Para pararlo:  powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1 -p'
    }
    Remove-Item $EnvF -ErrorAction SilentlyContinue
}

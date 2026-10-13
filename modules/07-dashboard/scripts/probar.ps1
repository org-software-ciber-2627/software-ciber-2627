# Prueba conjunta del Dashboard para Windows (PowerShell 5.1 o superior).
# Equivale a probar.sh: arranca el contenedor con docker compose, comprueba que responde y, si ya
# estan en la rama, prueba tambien los mocks de SOAR y Escaner. No toca tu .env ni deja nada
# arrancado al terminar. (El texto va sin tildes a proposito: PowerShell 5.1 lee mal los .ps1
# sin BOM con caracteres no ASCII.)
#
# Requisitos: Docker Desktop abierto.
# Uso (desde cualquier carpeta del clon):
#   powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1

$ErrorActionPreference = 'Continue'
$Raiz = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$Mod  = Join-Path $Raiz 'modules\07-dashboard'
$Proj = 'dashprueba'
$EnvF = Join-Path ([System.IO.Path]::GetTempPath()) ('probar-dashboard-' + [guid]::NewGuid().ToString('N') + '.env')
$script:Fallo = $false

function Ok($m)   { Write-Host "  OK    $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  FALLO $m" -ForegroundColor Red; $script:Fallo = $true }
function Step($m) { Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }

function Get-Text($url) {
    try { return (Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 5).Content } catch { return '' }
}
function Test-Url($url) {
    try { $null = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 3; return $true } catch { return $false }
}
# Cuenta cuantas veces aparece una clave JSON en una URL (misma idea que en probar.sh).
function Count-Key($url, $key) {
    $t = Get-Text $url
    return ([regex]::Matches($t, '"' + [regex]::Escape($key) + '"\s*:')).Count
}

try {
    Step 'Requisitos'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host 'Falta docker (instala Docker Desktop).'; exit 1
    }
    docker compose version *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host "Falta 'docker compose' (v2)."; exit 1 }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host 'Docker no responde (abre Docker Desktop y espera a que arranque).'; exit 1 }
    Ok 'docker y compose disponibles'

    # Variables: se parte de .env.example en un fichero temporal, asi no se pisa el .env del usuario.
    Copy-Item (Join-Path $Raiz '.env.example') $EnvF

    Step 'Arrancando el Dashboard (docker compose)'
    Push-Location $Raiz
    docker compose --env-file $EnvF -p $Proj up --build -d dashboard
    $codigo = $LASTEXITCODE
    Pop-Location
    if ($codigo -ne 0) { Write-Host 'docker compose fallo (puertos 8001-8007 ocupados?).'; exit 1 }

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

    Step 'Esperando a que respondan (max. 60 s)'
    $urls = @('http://localhost:8007/health')
    if ($HayMocks) { $urls += @('http://localhost:5001/health', 'http://localhost:5002/health') }
    foreach ($u in $urls) {
        for ($i = 0; $i -lt 30; $i++) {
            if (Test-Url $u) { break }
            Start-Sleep -Seconds 2
        }
    }

    Step 'Comprobaciones'
    if ((Get-Text 'http://localhost:8007/health') -match '"ok"') { Ok 'dashboard: /health responde 200' } else { Bad 'dashboard: /health' }
    if ((Get-Text 'http://localhost:8007/') -match 'Dashboard Principal') { Ok 'dashboard: la pagina principal se sirve' } else { Bad 'dashboard: pagina principal' }
    $n = Count-Key 'http://localhost:8007/mocks/siem-alerts.json' 'alert_id'
    if ($n -eq 4) { Ok 'dashboard: el mock del SIEM tiene 4 alertas' } else { Bad "dashboard: el mock del SIEM devuelve $n alertas (esperaba 4)" }
    if ((Get-Text 'http://localhost:8007/SIEM-alert.js') -match 'hora-actualizacion') { Ok 'dashboard: el JS actualiza la hora de ultima actualizacion' } else { Bad 'dashboard: falta la actualizacion de la hora' }
    if ($HayMocks) {
        $n = Count-Key 'http://localhost:5001/incidents' 'id'
        if ($n -eq 3) { Ok 'mock SOAR: GET /incidents devuelve 3 incidentes' } else { Bad "mock SOAR: /incidents devuelve $n (esperaba 3)" }
        $n = Count-Key 'http://localhost:5002/findings' 'id'
        if ($n -eq 3) { Ok 'mock Escaner: GET /findings devuelve 3 hallazgos' } else { Bad "mock Escaner: /findings devuelve $n (esperaba 3)" }
    } else {
        Write-Host '  (mocks de SOAR y Escaner: aun no estan en esta rama; se omiten)'
    }

    Write-Host ''
    if (-not $script:Fallo) { Write-Host 'TODO CORRECTO' -ForegroundColor Green } else { Write-Host 'HAY FALLOS (arriba)' -ForegroundColor Red }
    Write-Host ''
    Write-Host "Abre http://localhost:8007: 4 alertas ordenadas por severidad y hora real en 'Ultima actualizacion'."
    if (-not [Console]::IsInputRedirected) { Read-Host 'Pulsa Enter para parar todo y limpiar' | Out-Null }
    exit ([int]$script:Fallo)
}
finally {
    Step 'Limpiando'
    docker rm -f mock-soar mock-scanner *> $null
    Push-Location $Raiz
    docker compose --env-file $EnvF -p $Proj down *> $null
    Pop-Location
    Remove-Item $EnvF -ErrorAction SilentlyContinue
    Write-Host '  hecho'
}

#Requires -Version 5.1
<#
  Instalador de RedGuard
  Copia RedGuard a Documentos\RedGuard, crea el acceso directo del escritorio y lo abre.
  Si ya había una versión instalada, la actualiza sin borrar tus reportes, apodos ni historial.
#>
$ErrorActionPreference = 'Stop'
$origen  = Join-Path $PSScriptRoot 'app'
$destino = Join-Path $env:USERPROFILE 'Documents\RedGuard'

function Paso($t) { Write-Host "  · $t" -ForegroundColor Gray }

Clear-Host
Write-Host ''
Write-Host '  RedGuard - instalación' -ForegroundColor Cyan
Write-Host "  Equipo: $env:COMPUTERNAME   ·   Destino: $destino" -ForegroundColor DarkGray
Write-Host ''

if (-not (Test-Path (Join-Path $origen 'RedGuard.ps1'))) {
    Write-Host '  No encuentro la carpeta «app» junto al instalador.' -ForegroundColor Red
    Write-Host '  Descomprime el ZIP completo antes de ejecutar Instalar.bat.' -ForegroundColor Yellow
    return
}

try {
    Paso 'Quitando el bloqueo de archivos descargados de Internet'
    Get-ChildItem $origen -Recurse -File | Unblock-File

    Paso 'Copiando los archivos del programa'
    New-Item -ItemType Directory -Force -Path $destino | Out-Null
    foreach ($d in @('ui', 'datos', 'Reportes')) { New-Item -ItemType Directory -Force -Path (Join-Path $destino $d) | Out-Null }
    $archivos = Get-ChildItem $origen -Recurse -File
    foreach ($f in $archivos) {
        $rel = $f.FullName.Substring($origen.Length).TrimStart('\')
        $dst = Join-Path $destino $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
        Copy-Item $f.FullName $dst -Force
    }
    Get-ChildItem $destino -Recurse -File | Unblock-File

    Paso 'Revisando que los scripts no tengan errores'
    foreach ($s in @('RedGuard.ps1', 'RedGuard-Web.ps1')) {
        $tok = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $destino $s), [ref]$tok, [ref]$errs)
        if ($errs -and $errs.Length) { throw "El archivo $s tiene errores: $($errs[0].Message)" }
    }

    Paso 'Creando el acceso directo «RedGuard» en el escritorio'
    $esc = [Environment]::GetFolderPath('Desktop')
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut((Join-Path $esc 'RedGuard.lnk'))
    $lnk.TargetPath = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$destino\RedGuard-Web.ps1`""
    $lnk.WorkingDirectory = $destino
    $lnk.IconLocation = "$destino\RedGuard.ico,0"
    $lnk.Description = 'RedGuard - guardián de tu red'
    $lnk.Save()

    $abierto = $false
    $estado = Join-Path $destino 'datos\servidor.json'
    if (Test-Path $estado) {
        try { $s = [IO.File]::ReadAllText($estado) | ConvertFrom-Json; if (Get-Process -Id ([int]$s.pid) -ErrorAction Stop) { $abierto = $true } } catch {}
    }

    Write-Host ''
    if ($abierto) {
        Write-Host '  Listo. RedGuard ya estaba abierto y se actualizará solo en unos segundos.' -ForegroundColor Green
    } else {
        Paso 'Abriendo RedGuard'
        Start-Process "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$destino\RedGuard-Web.ps1`""
        Write-Host '  Listo. RedGuard se está abriendo y hará su primer escaneo.' -ForegroundColor Green
    }
    Write-Host '  Lo encontrarás en el escritorio (acceso directo «RedGuard») y junto al reloj.' -ForegroundColor Gray
} catch {
    Write-Host ''
    Write-Host "  No se pudo instalar: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ''

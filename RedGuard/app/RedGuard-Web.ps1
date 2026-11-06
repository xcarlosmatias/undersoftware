#Requires -Version 5.1
<#
  RedGuard - app HTML5
  Levanta un servidor solo para este equipo (127.0.0.1, con clave aleatoria), abre la
  interfaz en una ventana propia de Edge y deja un ícono junto al reloj que avisa de
  conexiones sospechosas aunque cierres la ventana.
#>
param([int]$Puerto = 0, [string]$Clave = '', [switch]$Reinicio)
$ErrorActionPreference = 'SilentlyContinue'
$Raiz   = $PSScriptRoot
$Motor  = Join-Path $Raiz 'RedGuard.ps1'
$UiFile = Join-Path $Raiz 'ui\index.html'
. $Motor -SoloFunciones

$Datos = Join-Path $Base 'datos'
New-Item -ItemType Directory -Force -Path $Datos | Out-Null
$LogSrv  = Join-Path $Datos 'servidor.log'
$EstadoF = Join-Path $Datos 'servidor.json'
$PsExe   = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"

function Write-Log($m) { try { Add-Content -Encoding UTF8 $LogSrv "$(Get-Date -Format s) $m" } catch {} }

function Open-Ventana($url) {
    $edge = Get-RutaEdge
    if ($edge) { Start-Process -FilePath $edge -ArgumentList "--app=`"$url`" --window-size=1340,900" }
    else { Start-Process $url }
}

# --- una sola instancia: si ya está corriendo, solo abre la ventana ---------
if (-not $Reinicio -and (Test-Path $EstadoF)) {
    try {
        $s = [IO.File]::ReadAllText($EstadoF, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $p = Get-Process -Id ([int]$s.pid) -ErrorAction Stop
        if ($p.ProcessName -match 'powershell') {
            $tc = New-Object System.Net.Sockets.TcpClient
            $tc.Connect('127.0.0.1', [int]$s.port); $tc.Close()
            Open-Ventana "http://127.0.0.1:$($s.port)/?t=$($s.token)"
            return
        }
    } catch {}
}

try { Install-Accesos } catch {}

# --- verificación de sintaxis de los scripts (queda en datos\verificacion.txt) ---
try {
    $lineas = @("Verificación $(Get-Date -Format s)")
    foreach ($f in @($Motor, $PSCommandPath)) {
        $tok = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$errs)
        $nErr = 0; if ($errs) { $nErr = $errs.Length }
        $lineas += "$(Split-Path $f -Leaf): $nErr error(es)"
        foreach ($e in $errs) { $lineas += "  línea $($e.Extent.StartLineNumber): $($e.Message)" }
    }
    [IO.File]::WriteAllText((Join-Path $Datos 'verificacion.txt'), ($lineas -join "`r`n"))
} catch {}

# --- servidor --------------------------------------------------------------
$listener = $null
for ($i = 0; $i -lt 15 -and -not $listener; $i++) {
    try {
        $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), $Puerto
        $l.Start(); $listener = $l
    } catch { Start-Sleep -Milliseconds 400 }
}
if (-not $listener) { $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0; $listener.Start() }
$Port  = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$Token = [guid]::NewGuid().ToString('N')
if ($Clave -match '^[0-9a-f]{32}$') { $Token = $Clave }
$Url   = "http://127.0.0.1:$Port/?t=$Token"
[IO.File]::WriteAllText($EstadoF, (ConvertTo-Json @{ pid = $PID; port = $Port; token = $Token } -Compress))
Write-Log "Servidor iniciado en el puerto $Port (PID $PID)"

$script:Salir = $false
$script:ScanProc = $null
$script:MonProc = $null
$script:MonUltimoInicio = [datetime]::MinValue

function Start-Monitor {
    Remove-Item (Join-Path $Datos 'detener-monitor') -Force
    $script:MonProc = Start-Process -FilePath $PsExe -WindowStyle Hidden -PassThru -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Motor`" -MonitorJson `"$Datos`""
    $script:MonUltimoInicio = Get-Date
}
function Start-Escaneo {
    if ($script:ScanProc -and -not $script:ScanProc.HasExited) { return }
    Remove-Item (Join-Path $Datos 'progreso.json') -Force
    [IO.File]::WriteAllText((Join-Path $Datos 'progreso.json'), '{"Estado":"Iniciando el escaneo...","Pct":2}')
    $script:ScanProc = Start-Process -FilePath $PsExe -WindowStyle Hidden -PassThru -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Motor`" -ExportarJson `"$Datos`""
    Write-Log "Escaneo iniciado (PID $($script:ScanProc.Id))"
}
$script:VulnProc = $null
function Start-Vuln {
    if ($script:VulnProc -and -not $script:VulnProc.HasExited) { return }
    [IO.File]::WriteAllText((Join-Path $Datos 'vuln-progreso.json'), '{"Estado":"Iniciando..."}')
    $script:VulnProc = Start-Process -FilePath $PsExe -WindowStyle Hidden -PassThru -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Motor`" -Vulnerabilidades `"$Datos`""
}
function Test-Escaneando { return [bool]($script:ScanProc -and -not $script:ScanProc.HasExited) }

$Utf8 = New-Object System.Text.UTF8Encoding $false
$Estados = @{ 200 = 'OK'; 204 = 'No Content'; 400 = 'Bad Request'; 403 = 'Forbidden'; 404 = 'Not Found'; 405 = 'Method Not Allowed'; 500 = 'Internal Server Error' }

function Send-Bytes($ns, [int]$code, [string]$tipo, [byte[]]$cuerpo, [string]$extra = '') {
    if (-not $cuerpo) { $cuerpo = [byte[]]@() }
    $cab = "HTTP/1.1 $code $($Estados[$code])`r`nContent-Type: $tipo`r`nContent-Length: $($cuerpo.Length)`r`n" +
           "Cache-Control: no-store`r`nConnection: close`r`nX-Content-Type-Options: nosniff`r`nX-Frame-Options: DENY`r`n$extra`r`n"
    $b = [Text.Encoding]::ASCII.GetBytes($cab)
    $ns.Write($b, 0, $b.Length)
    if ($cuerpo.Length) { $ns.Write($cuerpo, 0, $cuerpo.Length) }
    $ns.Flush()
}
function Send-Json($ns, $obj, [int]$code = 200) {
    Send-Bytes $ns $code 'application/json; charset=utf-8' ($Utf8.GetBytes((ConvertTo-Json $obj -Depth 6 -Compress)))
}
function Send-ArchivoJson($ns, $ruta) {
    for ($i = 0; $i -lt 5; $i++) {
        try { if (Test-Path $ruta) { Send-Bytes $ns 200 'application/json; charset=utf-8' ([IO.File]::ReadAllBytes($ruta)); return } else { break } }
        catch { Start-Sleep -Milliseconds 60 }
    }
    Send-Bytes $ns 204 'text/plain' $null
}
function Send-Texto($ns, [int]$code, $txt) { Send-Bytes $ns $code 'text/html; charset=utf-8' ($Utf8.GetBytes($txt)) }

function Read-Peticion($cliente) {
    $cliente.ReceiveTimeout = 3000
    $ns = $cliente.GetStream()
    $buf = New-Object byte[] 8192
    $ms = New-Object System.IO.MemoryStream
    $fin = -1; $txt = ''
    while ($fin -lt 0 -and $ms.Length -lt 65536) {
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -le 0) { break }
        $ms.Write($buf, 0, $n)
        $txt = [Text.Encoding]::ASCII.GetString($ms.ToArray())
        $fin = $txt.IndexOf("`r`n`r`n")
    }
    if ($fin -lt 0) { return $null }
    $lineas = $txt.Substring(0, $fin) -split "`r`n"
    $primera = $lineas[0] -split ' '
    if ($primera.Count -lt 2) { return $null }
    $cab = @{}
    for ($i = 1; $i -lt $lineas.Count; $i++) {
        $k = $lineas[$i].IndexOf(':')
        if ($k -gt 0) { $cab[$lineas[$i].Substring(0, $k).Trim().ToLower()] = $lineas[$i].Substring($k + 1).Trim() }
    }
    $crudo = $primera[1]; $ruta = $crudo; $q = @{}
    $qi = $crudo.IndexOf('?')
    if ($qi -ge 0) {
        $ruta = $crudo.Substring(0, $qi)
        foreach ($kv in ($crudo.Substring($qi + 1) -split '&')) {
            $par = $kv -split '=', 2
            if ($par[0]) { $v = ''; if ($par.Count -gt 1) { $v = [Uri]::UnescapeDataString(($par[1] -replace '\+', ' ')) }; $q[[Uri]::UnescapeDataString($par[0])] = $v }
        }
    }
    return @{ Metodo = $primera[0].ToUpper(); Ruta = $ruta; Q = $q; Cab = $cab; NS = $ns }
}

function Get-PidSeguro($q) {
    $n = 0
    if (-not [int]::TryParse([string]$q['pid'], [ref]$n)) { return 0 }
    if ($n -le 4 -or $n -eq $PID) { return 0 }
    if ($script:MonProc -and $n -eq $script:MonProc.Id) { return 0 }
    if ($script:ScanProc -and $n -eq $script:ScanProc.Id) { return 0 }
    return $n
}

function Get-ListaReportes {
    $lista = foreach ($f in (Get-ChildItem $DirReportes -Filter 'RedGuard_*.html' | Sort-Object LastWriteTime -Descending | Select-Object -First 60)) {
        $pdf = [IO.Path]::ChangeExtension($f.FullName, '.pdf')
        [pscustomobject]@{ Nombre = $f.Name; Fecha = $f.LastWriteTime.ToString('dd-MM-yyyy HH:mm'); Kb = [int]($f.Length / 1kb); Pdf = (Test-Path $pdf) }
    }
    return @($lista)
}

function Invoke-Ruta($req) {
    $ns = $req.NS
    if ($req.Cab['host'] -ne "127.0.0.1:$Port") { Send-Texto $ns 403 'Prohibido'; return }
    $tokHeader = ($req.Cab['x-rg-token'] -eq $Token)
    $tokQuery  = ($req.Q['t'] -eq $Token)
    $ruta = $req.Ruta; $m = $req.Metodo

    if ($ruta -eq '/' -or $ruta -eq '/index.html') {
        if (-not $tokQuery) { Send-Texto $ns 403 '<meta charset="utf-8"><body style="font-family:Segoe UI;background:#0e1116;color:#e6eaf0;padding:40px">Abre RedGuard desde el acceso directo <b>RedGuard</b> de tu escritorio.</body>'; return }
        $csp = "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`r`n"
        Send-Bytes $ns 200 'text/html; charset=utf-8' ([IO.File]::ReadAllBytes($UiFile)) $csp
        return
    }
    if ($ruta -eq '/favicon.ico' -or $ruta -eq '/icon.png') {
        $f = Join-Path $Raiz 'ui\icon.png'; $tipoI = 'image/png'
        if ($ruta -eq '/favicon.ico' -and (Test-Path (Join-Path $Raiz 'RedGuard.ico'))) { $f = Join-Path $Raiz 'RedGuard.ico'; $tipoI = 'image/x-icon' }
        if (Test-Path $f) { Send-Bytes $ns 200 $tipoI ([IO.File]::ReadAllBytes($f)) } else { Send-Bytes $ns 204 'text/plain' $null }
        return
    }

    if ($ruta -eq '/reporte') {
        if (-not ($tokQuery -or $tokHeader)) { Send-Texto $ns 403 'Prohibido'; return }
        $f = [string]$req.Q['f']
        if ($f -notmatch '^RedGuard_[\d_-]+\.(html|pdf)$') { Send-Texto $ns 404 'No encontrado'; return }
        $archivo = Join-Path $DirReportes $f
        if ($f -like '*.pdf' -and -not (Test-Path $archivo)) {
            $html = [IO.Path]::ChangeExtension($archivo, '.html')
            if (Test-Path $html) { [void](New-Pdf $html) }
        }
        if (-not (Test-Path $archivo)) { Send-Texto $ns 404 'Ese reporte ya no existe.'; return }
        $tipo = 'text/html; charset=utf-8'; $extra = ''
        if ($f -like '*.pdf') { $tipo = 'application/pdf'; $extra = "Content-Disposition: inline; filename=`"$f`"`r`n" }
        Send-Bytes $ns 200 $tipo ([IO.File]::ReadAllBytes($archivo)) $extra
        return
    }

    if (-not $ruta.StartsWith('/api/')) { Send-Texto $ns 404 'No encontrado'; return }
    if (-not $tokHeader) { Send-Json $ns @{ error = 'sin permiso' } 403; return }
    $accion = @('/api/escanear','/api/cerrar','/api/mostrar','/api/defender','/api/carpeta','/api/salir','/api/apodo','/api/vuln/actualizar') -contains $ruta
    if ($accion -and $m -ne 'POST') { Send-Json $ns @{ error = 'usa POST' } 405; return }

    switch ($ruta) {
        '/api/info'      { Send-Json $ns @{ Version = $Version; Equipo = $env:COMPUTERNAME; Admin = $EsAdmin; Escaneando = (Test-Escaneando) } }
        '/api/resultado' { Send-ArchivoJson $ns (Join-Path $Datos 'resultado.json') }
        '/api/vivo'      { Send-ArchivoJson $ns (Join-Path $Datos 'vivo.json') }
        '/api/progreso'  {
            $pr = $null
            try { $pr = [IO.File]::ReadAllText((Join-Path $Datos 'progreso.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json } catch {}
            $est = ''; $pct = 0; if ($pr) { $est = $pr.Estado; $pct = $pr.Pct }
            Send-Json $ns @{ Corriendo = (Test-Escaneando); Estado = $est; Pct = $pct }
        }
        '/api/escanear'  { Start-Escaneo; Send-Json $ns @{ ok = $true } }
        '/api/vuln'      { Send-ArchivoJson $ns (Join-Path $Datos 'vulnerabilidades.json') }
        '/api/vuln/actualizar' { Start-Vuln; Send-Json $ns @{ ok = $true } }
        '/api/vuln/estado' {
            $e = ''
            try { $e = ([IO.File]::ReadAllText((Join-Path $Datos 'vuln-progreso.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json).Estado } catch {}
            Send-Json $ns @{ Corriendo = [bool]($script:VulnProc -and -not $script:VulnProc.HasExited); Estado = $e }
        }
        '/api/reportes'  { Send-Json $ns @{ Lista = @(Get-ListaReportes) } }
        '/api/cerrar'    {
            $n = Get-PidSeguro $req.Q
            if (-not $n) { Send-Json $ns @{ ok = $false; msg = 'Ese proceso no se puede cerrar desde aquí.' }; break }
            $pr = Get-Process -Id $n
            $nom = [string]$pr.ProcessName
            Stop-Process -Id $n -Force
            Start-Sleep -Milliseconds 400
            if (Get-Process -Id $n) { Send-Json $ns @{ ok = $false; msg = "No se pudo cerrar $nom. Prueba abriendo RedGuard como administrador." } }
            else { Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) Cerrado desde la app: $nom PID $n"; Send-Json $ns @{ ok = $true; msg = "$nom fue cerrado." } }
        }
        '/api/mostrar'   {
            $n = Get-PidSeguro $req.Q
            $ruta2 = $null
            if ($n) { $ruta2 = (Get-CimInstance Win32_Process -Filter "ProcessId=$n").ExecutablePath }
            if ($ruta2 -and (Test-Path $ruta2)) { Start-Process explorer.exe "/select,`"$ruta2`""; Send-Json $ns @{ ok = $true } }
            else { Send-Json $ns @{ ok = $false; msg = 'No se pudo ubicar el archivo de ese programa.' } }
        }
        '/api/defender'  {
            $cmd = "`$host.UI.RawUI.WindowTitle='RedGuard - Análisis con Defender'; Write-Host ''; Write-Host '  Analizando tu equipo con Microsoft Defender (puede tardar unos minutos)…' -ForegroundColor Cyan; " +
                   "`$t=Get-Date; Start-MpScan -ScanType QuickScan; `$a=@(Get-MpThreatDetection | Where-Object { `$_.InitialDetectionTime -ge `$t }); " +
                   "if (`$a.Count) { Write-Host ('  Defender detectó ' + `$a.Count + ' amenaza(s). Abre Seguridad de Windows > Historial de protección.') -ForegroundColor Red } else { Write-Host '  Listo: Defender no encontró amenazas.' -ForegroundColor Green }; Write-Host ''; Read-Host '  Pulsa Enter para cerrar'"
            Start-Process -FilePath $PsExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
            Send-Json $ns @{ ok = $true }
        }
        '/api/apodo'     {
            $mac = ([string]$req.Q['mac']).ToUpper()
            $nom = ([string]$req.Q['nombre']).Trim()
            if ($nom.Length -gt 40) { $nom = $nom.Substring(0, 40) }
            if ($mac -notmatch '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$') { Send-Json $ns @{ ok = $false; msg = 'MAC inválida' }; break }
            $con = Get-Conocidos
            $e = $con[$mac]
            if ($e) { $e | Add-Member -Force -NotePropertyName Apodo -NotePropertyValue $nom }
            else { $con[$mac] = [pscustomobject]@{ Primera = (Get-Date).ToString('s'); Ultima = (Get-Date).ToString('s'); Apodo = $nom; Ip = ''; Fabricante = ''; Tipo = '' } }
            Save-Conocidos $con
            $rf = Join-Path $Datos 'resultado.json'
            try {
                $j = [IO.File]::ReadAllText($rf, [Text.Encoding]::UTF8) | ConvertFrom-Json
                foreach ($d in @($j.Dispositivos)) { if ($d.MAC -eq $mac) { $d.Apodo = $nom; $d.Nuevo = $false } }
                [IO.File]::WriteAllText($rf, (ConvertTo-Json $j -Depth 8 -Compress))
            } catch {}
            Send-Json $ns @{ ok = $true }
        }
        '/api/carpeta'   { Start-Process explorer.exe "`"$DirReportes`""; Send-Json $ns @{ ok = $true } }
        '/api/salir'     { Send-Json $ns @{ ok = $true }; $script:Salir = $true }
        default          { Send-Json $ns @{ error = 'no existe' } 404 }
    }
}

# --- ícono junto al reloj ----------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ni = New-Object System.Windows.Forms.NotifyIcon
$icoF = Join-Path $Raiz 'RedGuard.ico'
if (Test-Path $icoF) { try { $ni.Icon = New-Object System.Drawing.Icon $icoF, ([System.Windows.Forms.SystemInformation]::SmallIconSize) } catch { $ni.Icon = [System.Drawing.SystemIcons]::Shield } } else { $ni.Icon = [System.Drawing.SystemIcons]::Shield }
$ni.Text = 'RedGuard - vigilando tu red'
$menu = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add('Abrir RedGuard', $null, { Open-Ventana $Url })
[void]$menu.Items.Add('Escanear ahora', $null, { Start-Escaneo; Open-Ventana $Url })
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add('Cerrar RedGuard', $null, { $script:Salir = $true })
$ni.ContextMenuStrip = $menu
$ni.Add_DoubleClick({ Open-Ventana $Url })
$ni.Add_BalloonTipClicked({ Open-Ventana $Url })
$ni.Visible = $true

Start-Monitor
if ($Reinicio) {
    Write-Log "RedGuard se actualizó a la versión $Version"
    $ni.ShowBalloonTip(5000, "RedGuard se actualizó (v$Version)", 'La vigilancia sigue activa con la nueva versión.', [System.Windows.Forms.ToolTipIcon]::Info)
} else {
    Open-Ventana $Url
    $ni.ShowBalloonTip(5000, 'RedGuard está vigilando tu red', 'Te aviso aquí si aparece una conexión sospechosa. Clic derecho en el ícono para abrir o cerrar.', [System.Windows.Forms.ToolTipIcon]::Info)
}

# --- autoactualización: si cambian los scripts, RedGuard se reinicia solo ---
function Get-FirmaArchivos { return "$((Get-Item $Motor).LastWriteTimeUtc.Ticks)|$((Get-Item $PSCommandPath).LastWriteTimeUtc.Ticks)" }
function Test-SintaxisOk {
    foreach ($f in @($Motor, $PSCommandPath)) {
        $tok = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$errs)
        if ($errs -and $errs.Length) { return $false }
    }
    return $true
}
$script:FirmaIni = Get-FirmaArchivos
$script:CambioVisto = $null
$script:Reiniciar = $false

$pendientes = New-Object System.Collections.Generic.List[object]
$alertasVistas = @{}
$primeraLectura = $true
$ultimoChequeo = [datetime]::MinValue

try {
    while (-not $script:Salir) {
        while ($listener.Pending()) { $pendientes.Add(@{ C = $listener.AcceptTcpClient(); T = [datetime]::UtcNow }) }
        for ($i = $pendientes.Count - 1; $i -ge 0; $i--) {
            $p = $pendientes[$i]
            $listo = $false
            try { $listo = ($p.C.Available -gt 0) } catch {}
            if ($listo) {
                $pendientes.RemoveAt($i)
                try { $req = Read-Peticion $p.C; if ($req) { Invoke-Ruta $req } }
                catch { Write-Log "Error atendiendo petición: $($_.Exception.Message)" }
                finally { try { $p.C.Close() } catch {} }
            } elseif (([datetime]::UtcNow - $p.T).TotalSeconds -gt 15 -or -not $p.C.Connected) {
                $pendientes.RemoveAt($i); try { $p.C.Close() } catch {}
            }
        }

        if (((Get-Date) - $ultimoChequeo).TotalSeconds -ge 2) {
            $ultimoChequeo = Get-Date
            $fa = Get-FirmaArchivos
            if ($fa -ne $script:FirmaIni) {
                if (-not $script:CambioVisto) { $script:CambioVisto = Get-Date }
                elseif (((Get-Date) - $script:CambioVisto).TotalSeconds -ge 4 -and -not (Test-Escaneando)) {
                    if (Test-SintaxisOk) { Write-Log 'Se detectó una versión nueva; reiniciando'; $script:Reiniciar = $true; $script:Salir = $true }
                    else { Write-Log 'La versión nueva tiene errores de sintaxis; se mantiene la actual'; $script:FirmaIni = $fa; $script:CambioVisto = $null }
                }
            }
            # mantener vivo el monitor
            if ((-not $script:MonProc -or $script:MonProc.HasExited) -and ((Get-Date) - $script:MonUltimoInicio).TotalSeconds -gt 20) {
                Write-Log 'El monitor se detuvo; reiniciándolo'
                Start-Monitor
            }
            # avisos de alertas nuevas
            try {
                $vf = Join-Path $Datos 'vivo.json'
                if (Test-Path $vf) {
                    $v = [IO.File]::ReadAllText($vf, [Text.Encoding]::UTF8) | ConvertFrom-Json
                    $nuevas = @($v.Alertas | Where-Object { $_.Id -and -not $alertasVistas.ContainsKey($_.Id) })
                    foreach ($a in $nuevas) { $alertasVistas[$a.Id] = $true }
                    $graves = @($nuevas | Where-Object { $_.Nivel -in @('ALTO','MEDIO') })
                    if ($graves.Count -and -not $primeraLectura) {
                        $a = $graves[0]
                        $extraTxt = ''; if ($graves.Count -gt 1) { $extraTxt = " (y $($graves.Count - 1) más)" }
                        $ni.ShowBalloonTip(10000, "RedGuard: $($a.Titulo)$extraTxt", [string]$a.Detalle, [System.Windows.Forms.ToolTipIcon]::Warning)
                    } elseif ($graves.Count -and $primeraLectura) {
                        $ni.ShowBalloonTip(10000, "RedGuard encontró $($graves.Count) conexión(es) sospechosa(s)", 'Abre RedGuard > Tiempo real para revisarlas.', [System.Windows.Forms.ToolTipIcon]::Warning)
                    }
                    $primeraLectura = $false
                }
            } catch {}
        }

        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 20
    }
} finally {
    Write-Log 'Cerrando RedGuard'
    try { [IO.File]::WriteAllText((Join-Path $Datos 'detener-monitor'), '1') } catch {}
    Start-Sleep -Milliseconds 300
    if ($script:MonProc -and -not $script:MonProc.HasExited) { try { $script:MonProc.Kill() } catch {} }
    if ($script:ScanProc -and -not $script:ScanProc.HasExited) { try { $script:ScanProc.Kill() } catch {} }
    try { $listener.Stop() } catch {}
    $ni.Visible = $false; $ni.Dispose()
    Remove-Item $EstadoF -Force
    if ($script:Reiniciar) {
        Start-Process -FilePath $PsExe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Puerto $Port -Clave $Token -Reinicio"
    }
}

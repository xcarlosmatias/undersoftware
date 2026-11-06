#Requires -Version 5.1
<#
  RedGuard - Guardián de red para Windows  (motor de análisis)
  -------------------------------------------------------------
  Revisa a qué red estás conectado, dónde (IP pública y ubicación aproximada),
  qué dispositivos hay en tu red, qué programas tienen conexiones abiertas y
  si alguna es sospechosa, y el estado de Defender, firewall, RDP y proxy.

  Uso:
    RedGuard-App.bat      -> aplicación con ventana (recomendado)
    RedGuard.bat          -> revisión en consola + reporte HTML
    RedGuard-Monitor.bat  -> vigila en vivo y avisa si aparece algo sospechoso

  RedGuard complementa a Microsoft Defender; no lo reemplaza.
#>
param(
    [switch]$Monitor,
    [int]$Intervalo = 15,
    [switch]$SinAbrir,
    [switch]$SinEscaneoRed,
    [switch]$SinPreguntas,
    [switch]$SoloFunciones,
    [string]$ExportarJson,
    [string]$MonitorJson,
    [string]$Vulnerabilidades
)

$ErrorActionPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$Version     = '4.8'
$Base        = $PSScriptRoot
if (-not $Base) { $Base = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'RedGuard' }
$DirReportes = Join-Path $Base 'Reportes'
$Log         = Join-Path $Base 'alertas.log'
$PatronPropio = [regex]::Escape($Base) + '|RedGuard-Edge'
New-Item -ItemType Directory -Force -Path $DirReportes | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Base 'datos') | Out-Null

$EsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- reglas ----
$PuertosAltoRiesgo = @{
    4444 = 'Metasploit / reverse shell'; 4445 = 'reverse shell'; 1234 = 'reverse shell (netcat)'
    1337 = 'backdoor'; 31337 = 'Back Orifice'; 12345 = 'NetBus'; 27374 = 'SubSeven'
    6666 = 'botnet IRC'; 6667 = 'botnet IRC'; 6668 = 'botnet IRC'; 6669 = 'botnet IRC'
    5555 = 'RAT / ADB'; 7777 = 'RAT'; 9001 = 'Tor'; 9030 = 'Tor'; 9050 = 'Tor'; 9150 = 'Tor'
    3333 = 'minería de cripto (stratum)'; 14444 = 'minería de Monero'; 45700 = 'minería de cripto'
}
$PuertosAccesoRemoto = @{
    3389 = 'Escritorio remoto (RDP)'; 5900 = 'VNC'; 5901 = 'VNC'; 5938 = 'TeamViewer'
    4899 = 'Radmin'; 23 = 'Telnet'; 6568 = 'AnyDesk'; 7070 = 'AnyDesk'
}
$Shells = @('cmd','powershell','pwsh','powershell_ise','wscript','cscript','mshta','rundll32',
            'regsvr32','nc','nc64','ncat','netcat','socat','certutil','bitsadmin','msbuild','installutil')
$NombresSistema = @('svchost','lsass','csrss','winlogon','services','smss','spoolsv','explorer','dllhost',
                    'taskhostw','conhost','wininit','searchindexer','runtimebroker','sihost','ctfmon','lsm')
$NombresSenuelo = '^(win\d*|windows\d*|system\d*|sys\d*|svch0st|scvhost|svhost|svchosts|lsas|lsasss|csrs|expl0rer|winlogin|update|updater|winupdate|windowsupdate|msupdate|host|service)$'
$CarpetasRaras  = '\\(temp|tmp)\\|\\downloads\\|\\descargas\\|\\users\\public\\|\\\$recycle\.bin\\|\\perflogs\\|^[a-z]:\\programdata\\[^\\]+$'
$ColorNivel = @{ 'ALTO' = '#E5484D'; 'MEDIO' = '#F0A030'; 'BAJO' = '#C9B53A'; 'INFO' = '#3B82F6'; 'OK' = '#30A46C' }
$OrdenNivel = @{ 'ALTO' = 0; 'MEDIO' = 1; 'BAJO' = 2; 'INFO' = 3; 'OK' = 4 }

# Puertos que se prueban en cada dispositivo de la red para saber qué es y qué ofrece
$PuertosSondeo = @{
    22 = 'SSH (acceso remoto por consola)'; 23 = 'Telnet (acceso remoto SIN cifrar)'; 53 = 'DNS (resuelve nombres)'
    80 = 'Panel web'; 443 = 'Panel web seguro'; 445 = 'Carpetas compartidas de Windows (SMB)'; 554 = 'Video en vivo RTSP (cámaras)'
    631 = 'Impresión en red (IPP)'; 1883 = 'MQTT (domótica)'; 3389 = 'Escritorio remoto'; 5000 = 'UPnP / panel del equipo'
    5555 = 'Depuración de Android (ADB)'; 7000 = 'AirPlay'; 8008 = 'Google Cast'; 8009 = 'Google Cast'; 8080 = 'Panel web alterno'
    8443 = 'Panel web seguro alterno'; 9100 = 'Impresora en red'; 62078 = 'Sincronización de iPhone/iPad'
}
# Para qué sirve el puerto remoto de una conexión saliente
$ServiciosRemotos = @{
    443 = 'Web cifrada (HTTPS)'; 80 = 'Web sin cifrar (HTTP)'; 53 = 'DNS'; 853 = 'DNS cifrado'; 123 = 'Hora (NTP)'
    993 = 'Correo (IMAP)'; 995 = 'Correo (POP3)'; 465 = 'Envío de correo'; 587 = 'Envío de correo'; 25 = 'Correo (SMTP)'
    5228 = 'Servicios de Google (notificaciones)'; 5222 = 'Mensajería (WhatsApp / chat)'; 5223 = 'Notificaciones de Apple'
    3478 = 'Llamadas y video (STUN)'; 3479 = 'Llamadas y video'; 3480 = 'Llamadas y video'; 3481 = 'Llamadas y video'
    4070 = 'Spotify'; 1935 = 'Transmisión de video (RTMP)'; 8080 = 'Web alterna'; 8443 = 'Web cifrada alterna'; 22 = 'SSH'
    3389 = 'Escritorio remoto'; 445 = 'Carpetas compartidas (SMB)'; 7680 = 'Windows Update (entre equipos)'
    27015 = 'Juegos (Steam)'; 27036 = 'Steam'; 6881 = 'BitTorrent'; 1194 = 'VPN (OpenVPN)'; 51820 = 'VPN (WireGuard)'
    500 = 'VPN (IPsec)'; 4500 = 'VPN (IPsec)'; 8009 = 'Google Cast'; 8008 = 'Google Cast'; 1883 = 'MQTT (domótica)'; 8883 = 'MQTT cifrado (domótica)'
}
# Puertos que tu equipo deja abiertos: nombre, explicación y si es normal en Windows
$PuertosLocales = @{
    135   = @('RPC de Windows', 'Comunicación interna entre servicios de Windows.', 'Normal')
    139   = @('NetBIOS', 'Compartir archivos e impresoras con equipos antiguos.', 'Normal')
    445   = @('Carpetas compartidas (SMB)', 'Permite compartir archivos e impresoras en la red. Es normal en Windows; mantenlo solo en redes privadas.', 'Normal')
    5040  = @('Dispositivos conectados (CDP)', 'Servicio de Windows para «Continuar en el PC» y Uso compartido cercano.', 'Normal')
    7680  = @('Optimización de distribución', 'Windows Update comparte actualizaciones con otros PCs de tu red.', 'Normal')
    5357  = @('Descubrimiento de dispositivos (WSD)', 'Windows encuentra impresoras y equipos en la red.', 'Normal')
    2869  = @('UPnP / SSDP', 'Descubrimiento de dispositivos multimedia en la red.', 'Normal')
    5985  = @('Administración remota (WinRM)', 'Control remoto de Windows por PowerShell. Desactívalo si no lo usas.', 'Revisar')
    3389  = @('Escritorio remoto (RDP)', 'Permite controlar este PC desde otro equipo. Desactívalo si no lo usas.', 'Revisar')
    22    = @('Servidor SSH', 'Acceso remoto por consola a este equipo.', 'Revisar')
    21    = @('Servidor FTP', 'Transferencia de archivos sin cifrar.', 'Revisar')
    80    = @('Servidor web', 'Un programa está publicando una página web en tu red.', 'Depende')
    443   = @('Servidor web seguro', 'Un programa está publicando una página web cifrada.', 'Depende')
    8080  = @('Servidor web alterno', 'Suele ser una herramienta de desarrollo o el panel de un programa.', 'Depende')
    3000  = @('Servidor de desarrollo', 'Típico de herramientas de programación (Node, React).', 'Depende')
    5000  = @('Servidor de desarrollo / UPnP', 'Herramientas de programación (Python/Flask) o UPnP.', 'Depende')
    8000  = @('Servidor de desarrollo', 'Típico de Python (http.server, Django).', 'Depende')
    57621 = @('Spotify', 'Spotify busca otros dispositivos para Spotify Connect.', 'Normal')
    27036 = @('Steam', 'Transmisión local de juegos de Steam.', 'Normal')
    27040 = @('Steam', 'Descargas compartidas de Steam en tu red.', 'Normal')
    3306  = @('Base de datos MySQL', 'Una base de datos acepta conexiones desde la red.', 'Revisar')
    5432  = @('Base de datos PostgreSQL', 'Una base de datos acepta conexiones desde la red.', 'Revisar')
    1433  = @('SQL Server', 'Una base de datos acepta conexiones desde la red.', 'Revisar')
    27017 = @('Base de datos MongoDB', 'Una base de datos acepta conexiones desde la red.', 'Revisar')
    6379  = @('Redis', 'Una base de datos en memoria acepta conexiones desde la red.', 'Revisar')
    5900  = @('VNC (control remoto)', 'Permite ver y controlar este PC a distancia.', 'Revisar')
    5938  = @('TeamViewer', 'Control remoto de TeamViewer.', 'Depende')
    7070  = @('AnyDesk', 'Control remoto de AnyDesk.', 'Depende')
}
$EstadosTxt = @{ 'Established' = 'Conectada'; 'CloseWait' = 'Cerrándose'; 'SynSent' = 'Conectando…'; 'Listen' = 'Esperando conexiones'; 'TimeWait' = 'Terminando' }

$NotaCiber = 'Ningún programa por sí solo te hace invulnerable: la seguridad es una suma de capas. Un router bien configurado, un Wi-Fi con contraseña larga, Windows y tus apps al día, un antivirus activo (Microsoft Defender) y, sobre todo, buenos hábitos. La mayoría de los ataques no entran «hackeando» la red: entran porque alguien abre un adjunto, instala un programa falso o reutiliza una contraseña filtrada. RedGuard te muestra qué hay en tu red y con quién habla tu equipo para que detectes a tiempo lo que no cuadra, como un programa llamado win10.exe conectado al puerto 4444. Si encuentras algo que no reconoces: desconéctate de Internet, ejecuta un análisis completo con Microsoft Defender y cambia tus contraseñas desde otro dispositivo de confianza.'
$BuenasPracticas = @(
    @{ T = 'Activa la verificación en dos pasos'; D = 'En tu correo, banco y redes sociales. Es lo que más te protege si te roban una contraseña.' }
    @{ T = 'Usa un gestor de contraseñas'; D = 'Una contraseña distinta y larga para cada sitio (Bitwarden, 1Password o el de tu navegador).' }
    @{ T = 'Desconfía de enlaces y adjuntos'; D = 'El phishing es la puerta de entrada más común. Ante la duda, escribe tú mismo la dirección del sitio.' }
    @{ T = 'Descarga solo de sitios oficiales'; D = 'El malware se disfraza de archivos del sistema (win10.exe, svch0st.exe) o de programas «crackeados».' }
    @{ T = 'Actualiza todo, también el router'; D = 'Windows, navegador, apps y el firmware del router y de tus aparatos inteligentes.' }
    @{ T = 'Separa los aparatos inteligentes'; D = 'Conecta TV, parlantes, enchufes y cámaras a la red de invitados si tu router lo permite.' }
    @{ T = 'Respaldos 3-2-1'; D = 'Tres copias, en dos medios distintos, una fuera de casa (por ejemplo, en la nube). Te salva del ransomware.' }
    @{ T = 'Cuidado con el Wi-Fi público'; D = 'Usa los datos del celular o una VPN de confianza para bancos y trámites.' }
)
$NotaPrivacidad = 'Para darte estos detalles RedGuard consulta estos servicios: ipinfo.io (tu IP pública y ubicación aproximada), ip-api.com (a qué empresa y país pertenecen las direcciones a las que se conecta tu equipo) y macvendors.com / maclookup.app (solo el prefijo de fabricante de las MAC que no están en su base local). No envía tus archivos, nombres de programas ni tu tráfico.'

# ------------------------------------------------------------- utilidades ----
$script:Hallazgos = New-Object System.Collections.Generic.List[object]
$script:CacheFirma = @{}

function Add-Hallazgo($Nivel, $Titulo, $Detalle, $Consejo) {
    $script:Hallazgos.Add([pscustomobject]@{
        Nivel = $Nivel; Titulo = $Titulo; Detalle = $Detalle; Consejo = $Consejo; Color = $ColorNivel[$Nivel] })
}
function Get-Nivel([int]$p) {
    if ($p -ge 5) { 'ALTO' } elseif ($p -ge 3) { 'MEDIO' } elseif ($p -ge 1) { 'BAJO' } else { 'OK' }
}
function Get-Color($nivel) {
    switch ($nivel) { 'ALTO' { 'Red' } 'MEDIO' { 'Yellow' } 'BAJO' { 'DarkYellow' } 'INFO' { 'Cyan' } default { 'Green' } }
}
function Test-Loopback($ip) { return ([string]$ip -match '^(127\.|::1$)') }
function HtmlEnc($s) { return [System.Net.WebUtility]::HtmlEncode([string]$s) }

# La app con ventana pasa un hashtable sincronizado en $RedGuardSync para mostrar el progreso.
function Set-Progreso($texto, $pct) {
    if ($global:RedGuardSync) { $global:RedGuardSync.Estado = $texto; $global:RedGuardSync.Pct = $pct }
    elseif ($script:ArchivoProgreso) {
        try { [IO.File]::WriteAllText($script:ArchivoProgreso, (ConvertTo-Json @{ Estado = $texto; Pct = $pct } -Compress)) } catch {}
    }
    elseif (-not $SoloFunciones) { Write-Host "  $texto" -ForegroundColor DarkGray }
}

function Write-Titulo($t) {
    Write-Host ''
    Write-Host ('== ' + $t + ' ') -ForegroundColor Cyan -NoNewline
    Write-Host ('=' * [Math]::Max(3, 60 - $t.Length)) -ForegroundColor DarkCyan
}
function Write-Dato($k, $v, $color = 'White') {
    Write-Host ('  {0,-22}' -f $k) -ForegroundColor Gray -NoNewline
    Write-Host $v -ForegroundColor $color
}

function Get-Firma($ruta) {
    if (-not $ruta) { return $null }
    if ($script:CacheFirma.ContainsKey($ruta)) { return $script:CacheFirma[$ruta] }
    $s = Get-AuthenticodeSignature -FilePath $ruta
    $firmante = ''
    if ($s -and $s.SignerCertificate) { $firmante = ($s.SignerCertificate.Subject -replace '^CN="?([^,"]+).*$', '$1') }
    $estado = 'Desconocido'
    if ($s) { $estado = [string]$s.Status }
    $r = [pscustomobject]@{ Estado = $estado; Firmante = $firmante }
    $script:CacheFirma[$ruta] = $r
    return $r
}

# ------------------------------------------------------------------- red ----
function Get-InfoWifi {
    $out = netsh wlan show interfaces 2>$null
    if (-not $out) { return $null }
    $d = [ordered]@{}
    foreach ($l in $out) {
        if ($l -match '^\s*([^:]+?)\s*:\s*(.*)$') {
            $k = $matches[1].Trim(); $v = $matches[2].Trim()
            if (-not $d.Contains($k)) { $d[$k] = $v }
        }
    }
    function V($pat) { foreach ($k in $d.Keys) { if ($k -match $pat) { return $d[$k] } }; return $null }
    $ssid = V '^SSID$'
    if (-not $ssid) { return $null }
    return [pscustomobject]@{
        SSID      = $ssid
        BSSID     = V '^BSSID$'
        Seguridad = V '^(Autenticaci|Authentication)'
        Cifrado   = Convert-Cifrado (V '^(Cifrado|Cipher)')
        Senal     = V '^(Se.{1,3}al$|Signal)'
        Radio     = V '^(Tipo de radio|Radio type)'
        Banda     = V '^(Banda|Band)'
        Canal     = V '^(Canal|Channel)'
    }
}

function Get-IpPublica {
    try {
        $r = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
        if ($r.ip) { return [pscustomobject]@{ IP = $r.ip; Ciudad = $r.city; Region = $r.region; Pais = $r.country; Proveedor = $r.org; Coord = $r.loc } }
    } catch {}
    try {
        $r = Invoke-RestMethod -Uri 'http://ip-api.com/json/?lang=es' -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
        if ($r.query) { return [pscustomobject]@{ IP = $r.query; Ciudad = $r.city; Region = $r.regionName; Pais = $r.country; Proveedor = $r.isp; Coord = "$($r.lat),$($r.lon)" } }
    } catch {}
    return $null
}

function Convert-Cifrado($v) {
    if (-not $v) { return $v }
    $m = @{ '01' = 'WEP-40'; '02' = 'TKIP'; '04' = 'AES (CCMP)'; '05' = 'WEP-104'; '08' = 'GCMP'; '09' = 'GCMP-256'; '0a' = 'CCMP-256' }
    if ($v -match '(?i)(cifrado|cipher)\s*=\s*00-0f-ac:([0-9a-f]{2})') { $k = $matches[2].ToLower(); if ($m.ContainsKey($k)) { return $m[$k] } }
    if ($v -match '(?i)^ccmp$') { return 'AES (CCMP)' }
    return $v
}

# ------------------------------------------------------ fabricante por MAC --
$script:Oui = $null
function Test-MacPrivada($mac) {
    $hex = ([string]$mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    return ($hex.Length -ge 2 -and '26AE'.Contains($hex.Substring(1, 1)))
}
function Get-Fabricante($mac) {
    $hex = ([string]$mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($hex.Length -lt 6) { return '' }
    if (-not $script:Oui) {
        $script:Oui = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        foreach ($f in @((Join-Path $Base 'datos\oui.tsv'), (Join-Path $Base 'datos\oui-extra.tsv'))) {
            if (Test-Path $f) {
                foreach ($l in [IO.File]::ReadAllLines($f)) { $i = $l.IndexOf("`t"); if ($i -gt 0) { $script:Oui[$l.Substring(0, $i)] = $l.Substring($i + 1) } }
            }
        }
    }
    foreach ($n in @(9, 7, 6)) { if ($hex.Length -ge $n) { $k = $hex.Substring(0, $n); if ($script:Oui.ContainsKey($k)) { return $script:Oui[$k] } } }
    return ''
}
function Repair-Texto($t) {
    $t = [string]$t
    if ($t -match 'Ã|Â|â€') { try { $t = [Text.Encoding]::UTF8.GetString([Text.Encoding]::GetEncoding(28591).GetBytes($t)) } catch {} }
    return $t
}
function Find-FabricanteOnline($mac) {
    $hex = ([string]$mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($hex.Length -lt 6) { return '' }
    $p = $hex.Substring(0, 6)
    $c = ''
    try {
        Start-Sleep -Milliseconds 1100   # macvendors permite 1 consulta por segundo
        $t = Invoke-RestMethod -Uri ('https://api.macvendors.com/' + ($p -replace '(..)(?!$)', '$1:')) -TimeoutSec 4 -UseBasicParsing -ErrorAction Stop
        if ($t -is [string] -and $t.Trim() -and $t -notmatch '"errors"') { $c = (Repair-Texto $t).Trim() }
    } catch {}
    if ($c) {
        $c = ($c -replace '(?i)[,\s]+(inc\.?|ltd\.?|co\.?,?\s*ltd\.?|corporation|corp\.?|llc)\.?$', '').Trim()
        try { Add-Content (Join-Path $Base 'datos\oui-extra.tsv') "$p`t$c" -Encoding UTF8 } catch {}
        if ($script:Oui) { $script:Oui[$p] = $c }
        return $c
    }
    try {
        $r = Invoke-RestMethod -Uri "https://api.maclookup.app/v2/macs/$p" -TimeoutSec 4 -UseBasicParsing -ErrorAction Stop
        if ($r.found -and $r.company) {
            $c = ((Repair-Texto $r.company) -replace '(?i)[,\s]+(inc\.?|ltd\.?|co\.?,?\s*ltd\.?|corporation|corp\.?|llc)\.?$', '').Trim()
            try { Add-Content (Join-Path $Base 'datos\oui-extra.tsv') "$p`t$c" -Encoding UTF8 } catch {}
            if ($script:Oui) { $script:Oui[$p] = $c }
            return $c
        }
    } catch {}
    return ''
}

# ------------------------------------------- nombres de equipos en la red --
function Get-NombresNetBios($ips) {
    $res = @{}
    if (-not $ips) { return $res }
    $u = New-Object System.Net.Sockets.UdpClient 0
    $u.Client.ReceiveTimeout = 250
    $q = [byte[]](@(0x52, 0x47, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 0x43, 0x4B) + (@(0x41) * 30) + @(0, 0, 0x21, 0, 1))
    foreach ($ip in $ips) { try { [void]$u.Send($q, $q.Length, [string]$ip, 137) } catch {} }
    $fin = (Get-Date).AddMilliseconds(1300)
    while ((Get-Date) -lt $fin) {
        try {
            $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $b = $u.Receive([ref]$ep)
            $ip = $ep.Address.ToString()
            if ($b.Length -gt 57) {
                $n = [int]$b[56]; $o = 57
                for ($i = 0; $i -lt $n -and ($o + 18) -le $b.Length; $i++) {
                    $nombre = [Text.Encoding]::ASCII.GetString($b, $o, 15).Trim()
                    $grupo = ($b[$o + 16] -band 0x80) -ne 0
                    if ($b[$o + 15] -eq 0 -and -not $grupo -and $nombre) { $res[$ip] = $nombre; break }
                    $o += 18
                }
            }
        } catch {}
    }
    $u.Close()
    return $res
}

function New-ConsultaDns([string]$nombre, [int]$tipo) {
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([byte[]](0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($et in $nombre.Split('.')) { $e = [Text.Encoding]::ASCII.GetBytes($et); $b.Add([byte]$e.Length); $b.AddRange($e) }
    $b.Add(0); $b.Add([byte]($tipo -shr 8)); $b.Add([byte]($tipo -band 0xFF)); $b.Add(0); $b.Add(1)
    return $b.ToArray()
}
function Read-NombreDns([byte[]]$b, [int]$o) {
    $partes = New-Object System.Collections.Generic.List[string]
    $saltos = 0; $fin = -1
    while ($o -lt $b.Length -and $saltos -lt 20) {
        $len = [int]$b[$o]
        if ($len -eq 0) { $o++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($fin -lt 0) { $fin = $o + 2 }
            $o = (($len -band 0x3F) -shl 8) + [int]$b[$o + 1]; $saltos++; continue
        }
        if ($o + 1 + $len -gt $b.Length) { break }
        $partes.Add([Text.Encoding]::UTF8.GetString($b, $o + 1, $len)); $o += $len + 1
    }
    if ($fin -lt 0) { $fin = $o }
    return @(($partes -join '.'), $fin)
}
function Get-NombresMdns($ips) {
    $res = @{}
    if (-not $ips) { return $res }
    $u = New-Object System.Net.Sockets.UdpClient 0
    $u.Client.ReceiveTimeout = 250
    foreach ($ip in $ips) {
        $p = ([string]$ip).Split('.'); [array]::Reverse($p)
        $q = New-ConsultaDns (($p -join '.') + '.in-addr.arpa') 12
        try { [void]$u.Send($q, $q.Length, [string]$ip, 5353) } catch {}
    }
    $fin = (Get-Date).AddMilliseconds(1300)
    while ((Get-Date) -lt $fin) {
        try {
            $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $b = $u.Receive([ref]$ep)
            $ip = $ep.Address.ToString()
            if ($b.Length -lt 12) { continue }
            $qd = ([int]$b[4] -shl 8) + $b[5]; $an = ([int]$b[6] -shl 8) + $b[7]
            $o = 12
            for ($i = 0; $i -lt $qd; $i++) { $o = (Read-NombreDns $b $o)[1] + 4 }
            for ($i = 0; $i -lt $an -and ($o + 10) -le $b.Length; $i++) {
                $o = (Read-NombreDns $b $o)[1]
                $tipo = ([int]$b[$o] -shl 8) + $b[$o + 1]; $rdlen = ([int]$b[$o + 8] -shl 8) + $b[$o + 9]; $o += 10
                if ($tipo -eq 12) { $n = (Read-NombreDns $b $o)[0]; if ($n) { $res[$ip] = ($n -replace '\.local\.?$', ''); break } }
                $o += $rdlen
            }
        } catch {}
    }
    $u.Close()
    return $res
}

function Get-InfoSsdp {
    $res = @{}
    $u = New-Object System.Net.Sockets.UdpClient 0
    $u.Client.ReceiveTimeout = 300
    $msg = [Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: ssdp:all`r`n`r`n")
    try { [void]$u.Send($msg, $msg.Length, '239.255.255.250', 1900); Start-Sleep -Milliseconds 120; [void]$u.Send($msg, $msg.Length, '239.255.255.250', 1900) } catch {}
    $fin = (Get-Date).AddMilliseconds(2600)
    while ((Get-Date) -lt $fin) {
        try {
            $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $txt = [Text.Encoding]::UTF8.GetString($u.Receive([ref]$ep))
            $ip = $ep.Address.ToString()
            if (-not $res.ContainsKey($ip)) { $res[$ip] = @{ Server = ''; Location = New-Object System.Collections.Generic.List[string]; Nombre = ''; Fabricante = ''; Modelo = ''; TipoUpnp = '' } }
            foreach ($l in ($txt -split "`r`n")) {
                if ($l -match '^(?i)SERVER:\s*(.+)$') { $res[$ip].Server = $matches[1].Trim() }
                elseif ($l -match '^(?i)LOCATION:\s*(\S+)') { if (-not $res[$ip].Location.Contains($matches[1])) { $res[$ip].Location.Add($matches[1]) } }
            }
        } catch {}
    }
    $u.Close()
    $n = 0
    foreach ($ip in @($res.Keys)) {
        if ($n -ge 10) { break }
        foreach ($loc in ($res[$ip].Location | Select-Object -First 2)) {
            try {
                $uri = [Uri]$loc
                if ($uri.Host -ne $ip -or $uri.Scheme -ne 'http') { continue }
                $n++
                $cont = (Invoke-WebRequest -Uri $loc -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop).Content
                if ($cont -is [byte[]]) { $cont = [Text.Encoding]::UTF8.GetString($cont) }
                $cont = ([string]$cont).TrimStart([char]0xFEFF).Trim()
                $x = [xml]$cont
                $dev = $x.root.device
                if ($dev) {
                    $res[$ip].Nombre = [string]$dev.friendlyName; $res[$ip].Fabricante = [string]$dev.manufacturer
                    $res[$ip].Modelo = [string]$dev.modelName; $res[$ip].TipoUpnp = [string]$dev.deviceType
                    break
                }
            } catch {}
        }
    }
    return $res
}

function Get-PuertosAbiertos($ips) {
    $tareas = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $ips) {
        foreach ($pt in $PuertosSondeo.Keys) {
            $tc = New-Object System.Net.Sockets.TcpClient
            try { $tareas.Add(@{ IP = [string]$ip; P = [int]$pt; C = $tc; T = $tc.ConnectAsync([string]$ip, [int]$pt) }) } catch { $tc.Close() }
        }
    }
    if ($tareas.Count) {
        $arr = [System.Threading.Tasks.Task[]]@($tareas | ForEach-Object { $_.T })
        try { [void][System.Threading.Tasks.Task]::WaitAll($arr, 1500) } catch {}
    }
    $res = @{}
    foreach ($t in $tareas) {
        if ([string]$t.T.Status -eq 'RanToCompletion' -and $t.C.Connected) {
            if (-not $res.ContainsKey($t.IP)) { $res[$t.IP] = New-Object System.Collections.Generic.List[int] }
            $res[$t.IP].Add($t.P)
        }
        try { $t.C.Close() } catch {}
    }
    return $res
}

function Get-TipoDispositivo($d, $gw) {
    $v = ([string]$d.Fabricante).ToLower()
    $n = (@($d.Nombre, $d.NombreUpnp, $d.Modelo, $d.Servidor) -join ' ').ToLower()
    $p = @($d.Puertos | ForEach-Object { [int]$_.P })
    $tu = ([string]$d.TipoUpnp).ToLower()
    if ($d.EsEste) { return @('pc', 'Este equipo') }
    if ($d.IP -eq $gw) { return @('router', 'Router principal (puerta de enlace)') }
    $mid = [string]$d.ModeloId; $sv = [string]$d.Servicios
    if ($mid -match '^iPhone') { return @('celular', 'iPhone') }
    if ($mid -match '^iPad') { return @('tablet', 'iPad') }
    if ($mid -match '^AppleTV') { return @('streaming', 'Apple TV') }
    if ($mid -match '^AudioAccessory') { return @('altavoz', 'HomePod') }
    if ($mid -match '^Watch') { return @('celular', 'Apple Watch') }
    if ($mid -match '^(Mac|iMac)') { return @('pc', 'Mac') }
    if ($sv -match 'Apple Continuidad|Sincronización Apple') {
        if ($n -match 'ipad') { return @('tablet', 'iPad') }
        if ($n -match 'mac') { return @('pc', 'Mac') }
        return @('celular', 'iPhone o iPad')
    }
    if ($sv -match 'Google Cast' -and $v -notmatch 'hisense|qingdao|tcl|lg|samsung|sony') {
        if ($mid -match '(?i)chromecast|google tv') { return @('streaming', 'Chromecast / Google TV') }
        if ($mid -match '(?i)nest|home|speaker|mini|audio') { return @('altavoz', 'Google Nest') }
    }
    if ($sv -match 'HomeKit' -and $p.Count -eq 0) { return @('iot', 'Accesorio HomeKit') }
    if ($v -match 'hisense|qingdao intelligent|tcl|vizio|tp vision|skyworth' -or ($v -match 'lg electronics|samsung|sony' -and ($p -contains 8009 -or $tu -match 'mediarenderer'))) {
        if ($p -contains 8009) { return @('tv', 'Smart TV (con Google Cast)') }
        return @('tv', 'Smart TV')
    }
    if ($n -match 'iphone') { return @('celular', 'iPhone') }
    if ($n -match 'ipad') { return @('tablet', 'iPad') }
    if ($n -match 'apple ?tv|appletv') { return @('streaming', 'Apple TV') }
    if ($n -match 'macbook|imac|mac-?mini|mac-?studio|mac-?pro') { return @('pc', 'Mac') }
    if ($n -match 'chromecast|google ?tv') { return @('streaming', 'Chromecast / Google TV') }
    if ($n -match 'nest|google ?home|google-home') { return @('altavoz', 'Google Nest (parlante o pantalla)') }
    if ($n -match '\becho\b|alexa') { return @('altavoz', 'Amazon Echo (Alexa)') }
    if ($n -match 'fire ?tv|firetv') { return @('streaming', 'Amazon Fire TV') }
    if ($n -match 'xbox') { return @('consola', 'Xbox') }
    if ($n -match 'playstation|\bps[45]\b') { return @('consola', 'PlayStation') }
    if ($n -match 'printer|impresora|laserjet|deskjet|officejet') { return @('impresora', 'Impresora') }
    if ($tu -match 'mediarenderer' -or $n -match '\btv\b|bravia|webos|tizen|roku|smart ?tv|android ?tv') { return @('tv', 'Smart TV') }
    if ($tu -match 'internetgatewaydevice|wfadevice' -or $n -match 'router|repeater|extender|mesh|\bont\b|gpon') { return @('red', 'Equipo de red (router, repetidor u ONT)') }
    if ($p -contains 62078) { return @('celular', 'iPhone o iPad') }
    if ($p -contains 8009 -or $p -contains 8008) {
        if ($v -match 'google') { return @('altavoz', 'Google Nest / Chromecast') }
        return @('tv', 'TV o equipo compatible con Google Cast')
    }
    if ($p -contains 9100 -or $p -contains 631) { return @('impresora', 'Impresora') }
    if ($p -contains 554 -or $v -match 'hikvision|dahua|ezviz|reolink|wyze|imou|uniview|hanwha vision|axis comm') { return @('camara', 'Cámara IP') }
    if ($v -match 'espressif|tuya|shelly|itead|sonoff|lifx|signify|philips lighting|broadlink|wiz connected|meross|sengled|nanoleaf|ecovacs|roborock|dreame') { return @('iot', 'Dispositivo inteligente (enchufe, foco, sensor o robot)') }
    if ($v -match 'lg innotek') { return @('iot', 'Aparato LG (TV, electrodoméstico o módulo inteligente)') }
    if ($v -match 'midea|gree electric|daikin|haier|carrier|whirlpool|bsh haus|electrolux|aux air') { return @('clima', 'Electrodoméstico inteligente (aire acondicionado u otro)') }
    if ($v -match 'amazon') { return @('altavoz', 'Amazon (Echo, Fire TV o Kindle)') }
    if ($v -match 'google') { return @('altavoz', 'Google (Nest, Chromecast o Pixel)') }
    if ($v -match 'sonos|bose|harman|jbl') { return @('altavoz', 'Parlante inteligente') }
    if ($v -match 'roku|tcl|hisense|vizio|lg electronics|sony corp|tp vision') { return @('tv', 'Smart TV o equipo multimedia') }
    if ($v -match 'sony interactive|nintendo') { return @('consola', 'Consola de juegos') }
    if ($v -match 'synology|qnap|western digital|seagate|buffalo') { return @('nas', 'Disco en red (NAS)') }
    if ($v -match 'hp inc|hewlett|seiko epson|canon|brother|xerox|lexmark|kyocera|ricoh') { return @('impresora', 'Impresora') }
    if ($p -contains 445 -or $p -contains 3389) { return @('pc', 'Computador con Windows') }
    if ($v -match 'huawei|zte|tp-link|mitrastar|sagemcom|arris|technicolor|netgear|ubiquiti|mikrotik|tenda|d-link|askey|zyxel|cisco|linksys|nokia|fiberhome|sercomm|mercusys|asustek|eero|plume') {
        if ($p -contains 53 -or $p -contains 80 -or $p -contains 443) { return @('red', 'Equipo de red (router, repetidor u ONT)') }
        if ($v -match 'huawei|zte') { return @('celular', 'Celular, tablet o equipo de red') }
        return @('red', 'Equipo de red (router, repetidor u ONT)')
    }
    if ($v -match 'apple') { return @('celular', 'Dispositivo Apple (iPhone, iPad, Mac o Apple TV)') }
    if ($v -match 'samsung') { return @('celular', 'Samsung (celular, tablet o TV)') }
    if ($v -match 'xiaomi') { return @('celular', 'Xiaomi (celular o dispositivo inteligente)') }
    if ($v -match 'motorola|oppo|vivo mobile|oneplus|realme|honor|nothing tech') { return @('celular', 'Celular') }
    if ($v -match 'intel|realtek|liteon|lite-on|azurewave|hon hai|foxconn|qualcomm|mediatek|rivet|dell|lenovo|micro-star|gigabyte|microsoft|hanwha nxmd|chicony|wistron|quanta|compal|pegatron|universal global') { return @('pc', 'Computador (PC o notebook)') }
    if ($d.MacPrivada) { return @('celular', 'Celular o tablet (usa MAC privada)') }
    if ($p -contains 22) { return @('pc', 'Equipo con Linux o servidor') }
    if ($p -contains 80 -or $p -contains 443) { return @('iot', 'Equipo con panel web') }
    return @('desconocido', 'Dispositivo sin identificar')
}

function Get-Conocidos {
    $f = Join-Path $Base 'datos\dispositivos.json'
    $h = @{}
    if (Test-Path $f) {
        try { $o = [IO.File]::ReadAllText($f) | ConvertFrom-Json; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } } catch {}
    }
    return $h
}
function Save-Conocidos($h) {
    $f = Join-Path $Base 'datos\dispositivos.json'
    try { New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null; [IO.File]::WriteAllText($f, (ConvertTo-Json $h -Depth 4)) } catch {}
}
function Get-DescDisp($d) {
    $t = @($d.Apodo, $d.Nombre, $d.NombreUpnp) | Where-Object { $_ } | Select-Object -First 1
    $s = [string]$d.Tipo
    if ($t) { $s = "$t ($($d.Tipo))" }
    if ($d.Fabricante) { $s += " · $($d.Fabricante)" }
    return $s
}

# ------------------------------------------ Bonjour / mDNS (Apple, Google) --
function Read-RegistrosDns([byte[]]$b) {
    $regs = New-Object System.Collections.Generic.List[object]
    if ($b.Length -lt 12) { return @() }
    $qd = ([int]$b[4] -shl 8) + $b[5]; $an = ([int]$b[6] -shl 8) + $b[7]
    $nsr = ([int]$b[8] -shl 8) + $b[9]; $ar = ([int]$b[10] -shl 8) + $b[11]
    $o = 12
    for ($i = 0; $i -lt $qd; $i++) { $o = (Read-NombreDns $b $o)[1] + 4 }
    $total = $an + $nsr + $ar
    for ($i = 0; $i -lt $total -and ($o + 10) -le $b.Length; $i++) {
        $nr = Read-NombreDns $b $o
        $nom = [string]$nr[0]; $o = [int]$nr[1]
        if ($o + 10 -gt $b.Length) { break }
        $tipo = ([int]$b[$o] -shl 8) + $b[$o + 1]
        $rdlen = ([int]$b[$o + 8] -shl 8) + $b[$o + 9]
        $o += 10
        if ($o + $rdlen -gt $b.Length) { break }
        $val = $null
        if ($tipo -eq 1 -and $rdlen -eq 4) { $val = "$($b[$o]).$($b[$o + 1]).$($b[$o + 2]).$($b[$o + 3])" }
        elseif ($tipo -eq 12) { $val = [string](Read-NombreDns $b $o)[0] }
        elseif ($tipo -eq 33 -and $rdlen -gt 6) { $val = [string](Read-NombreDns $b ($o + 6))[0] }
        elseif ($tipo -eq 16) {
            $tx = @{}; $p = $o
            while ($p -lt ($o + $rdlen)) {
                $l = [int]$b[$p]; $p++
                if ($l -gt 0 -and ($p + $l) -le ($o + $rdlen)) {
                    $s = [Text.Encoding]::UTF8.GetString($b, $p, $l)
                    $k = $s.IndexOf('=')
                    if ($k -gt 0) { $tx[$s.Substring(0, $k).ToLower()] = $s.Substring($k + 1) }
                }
                $p += $l
            }
            $val = $tx
        }
        if ($null -ne $val) { $regs.Add([pscustomobject]@{ Nombre = $nom; Tipo = $tipo; Valor = $val; Origen = '' }) }
        $o += $rdlen
    }
    return $regs.ToArray()
}

function Get-InfoBonjour {
    $res = @{}
    $tipos = @('_companion-link._tcp.local', '_apple-mobdev2._tcp.local', '_rdlink._tcp.local', '_device-info._tcp.local',
               '_airplay._tcp.local', '_raop._tcp.local', '_googlecast._tcp.local', '_hap._tcp.local', '_homekit._tcp.local',
               '_spotify-connect._tcp.local', '_ipp._tcp.local', '_printer._tcp.local', '_smb._tcp.local', '_amzn-wplay._tcp.local',
               '_androidtvremote2._tcp.local', '_sleep-proxy._udp.local')
    $q = New-Object System.Collections.Generic.List[byte]
    $q.AddRange([byte[]](0, 0, 0, 0, 0, [byte]$tipos.Count, 0, 0, 0, 0, 0, 0))
    foreach ($t in $tipos) {
        foreach ($et in $t.Split('.')) { $e = [Text.Encoding]::ASCII.GetBytes($et); $q.Add([byte]$e.Length); $q.AddRange($e) }
        $q.Add(0); $q.AddRange([byte[]](0, 12, 0x80, 1))
    }
    $pkt = $q.ToArray()
    $u = New-Object System.Net.Sockets.UdpClient 0
    $u.Client.ReceiveTimeout = 300
    try { [void]$u.Send($pkt, $pkt.Length, '224.0.0.251', 5353); Start-Sleep -Milliseconds 300; [void]$u.Send($pkt, $pkt.Length, '224.0.0.251', 5353) } catch {}
    $regs = New-Object System.Collections.Generic.List[object]
    $fin = (Get-Date).AddMilliseconds(2900)
    while ((Get-Date) -lt $fin) {
        try {
            $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $b = $u.Receive([ref]$ep)
            $src = $ep.Address.ToString()
            foreach ($r in (Read-RegistrosDns $b)) { $r.Origen = $src; $regs.Add($r) }
        } catch {}
    }
    $u.Close()

    $aRec = @{}; $srv = @{}; $txt = @{}
    foreach ($r in $regs) {
        $n = $r.Nombre.ToLower()
        if ($r.Tipo -eq 1) { $aRec[$n] = $r.Valor }
        elseif ($r.Tipo -eq 33) { $srv[$n] = $r.Valor }
        elseif ($r.Tipo -eq 16) { $txt[$n] = $r.Valor }
    }
    foreach ($r in $regs) {
        if ($r.Tipo -ne 12) { continue }
        $inst = [string]$r.Valor; $il = $inst.ToLower()
        $hostN = [string]$srv[$il]
        $ip = $null
        if ($hostN) { $ip = $aRec[$hostN.ToLower()] }
        if (-not $ip) { $ip = $r.Origen }
        if (-not $res.ContainsKey($ip)) { $res[$ip] = @{ Nombres = (New-Object System.Collections.Generic.List[string]); Servicios = (New-Object System.Collections.Generic.List[string]); Host = ''; Txt = @{} } }
        $e = $res[$ip]
        $corto = ($inst -replace '\._[^.]+\._(tcp|udp)\.local\.?$', '') -replace '^[0-9A-Fa-f]{12}@', ''
        if ($corto -and $corto -notmatch '^[0-9a-f]{12,}$' -and -not $e.Nombres.Contains($corto)) { $e.Nombres.Add($corto) }
        $svc = ($r.Nombre -replace '\.local\.?$', '')
        if (-not $e.Servicios.Contains($svc)) { $e.Servicios.Add($svc) }
        if ($hostN -and -not $e.Host) { $e.Host = ($hostN -replace '\.local\.?$', '') }
        $t = $txt[$il]
        if ($t) { foreach ($k in @($t.Keys)) { $e.Txt[$k] = $t[$k] } }
    }
    return $res
}

function Get-NombreApple($id) {
    $id = [string]$id
    $m = @{
        'iPhone17,1' = 'iPhone 16 Pro'; 'iPhone17,2' = 'iPhone 16 Pro Max'; 'iPhone17,3' = 'iPhone 16'; 'iPhone17,4' = 'iPhone 16 Plus'; 'iPhone17,5' = 'iPhone 16e'
        'iPhone16,1' = 'iPhone 15 Pro'; 'iPhone16,2' = 'iPhone 15 Pro Max'; 'iPhone15,4' = 'iPhone 15'; 'iPhone15,5' = 'iPhone 15 Plus'
        'iPhone15,2' = 'iPhone 14 Pro'; 'iPhone15,3' = 'iPhone 14 Pro Max'; 'iPhone14,7' = 'iPhone 14'; 'iPhone14,8' = 'iPhone 14 Plus'
        'iPhone14,2' = 'iPhone 13 Pro'; 'iPhone14,3' = 'iPhone 13 Pro Max'; 'iPhone14,4' = 'iPhone 13 mini'; 'iPhone14,5' = 'iPhone 13'; 'iPhone14,6' = 'iPhone SE (3.ª gen.)'
        'iPhone13,1' = 'iPhone 12 mini'; 'iPhone13,2' = 'iPhone 12'; 'iPhone13,3' = 'iPhone 12 Pro'; 'iPhone13,4' = 'iPhone 12 Pro Max'
        'iPhone12,1' = 'iPhone 11'; 'iPhone12,3' = 'iPhone 11 Pro'; 'iPhone12,5' = 'iPhone 11 Pro Max'; 'iPhone12,8' = 'iPhone SE (2.ª gen.)'
    }
    if ($m.ContainsKey($id)) { return $m[$id] }
    if ($id -match '^iPhone') { return "iPhone ($id)" }
    if ($id -match '^iPad') { return "iPad ($id)" }
    if ($id -match '^AppleTV') { return "Apple TV ($id)" }
    if ($id -match '^AudioAccessory') { return "HomePod ($id)" }
    if ($id -match '^Watch') { return "Apple Watch ($id)" }
    if ($id -match '^(Mac|iMac)') { return "Mac ($id)" }
    return $id
}

function Get-DispositivosRed($cfg) {
    if (-not $cfg) { return @() }
    $ip = $cfg.IPv4Address | Select-Object -First 1
    $partes = $ip.IPAddress -split '\.'
    $pref24 = ($partes[0..2]) -join '.'
    if (-not $SinEscaneoRed -and [int]$ip.PrefixLength -ge 22) {
        $tareas = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
        foreach ($n in 1..254) {
            try { $pg = New-Object System.Net.NetworkInformation.Ping; $tareas.Add($pg.SendPingAsync("$pref24.$n", 500)) } catch {}
        }
        try { [void][System.Threading.Tasks.Task]::WaitAll($tareas.ToArray(), 4000) } catch {}
    }
    $filtroV4 = {
        ([string]$_.State) -in @('Reachable','Stale','Delay','Probe','Permanent') -and
        $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and
        $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.' -and $_.IPAddress -notmatch '\.255$'
    }
    # Bonjour y SSDP: los iPhone y TV responden aquí aunque ignoren los pings
    Set-Progreso 'Buscando celulares, equipos Apple y TV (Bonjour / UPnP)...' 33
    $bonjour = Get-InfoBonjour
    $ssdp = Get-InfoSsdp
    # segunda pasada, con más paciencia, para despertar equipos dormidos
    if (-not $SinEscaneoRed -and [int]$ip.PrefixLength -ge 22) {
        Set-Progreso 'Despertando equipos dormidos (segunda pasada)...' 40
        $ya = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $cfg.InterfaceIndex | Where-Object $filtroV4 | ForEach-Object { [string]$_.IPAddress })
        $extra = @($bonjour.Keys) + @($ssdp.Keys) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
        $objetivo = @((1..254 | ForEach-Object { "$pref24.$_" }) + $extra | Select-Object -Unique | Where-Object { $ya -notcontains $_ })
        $tareas = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
        $tcps = New-Object System.Collections.Generic.List[object]
        foreach ($x in $objetivo) {
            try { $pg = New-Object System.Net.NetworkInformation.Ping; $tareas.Add($pg.SendPingAsync($x, 1500)) } catch {}
            # puerto 62078: el iPhone lo deja abierto para sincronizar por Wi-Fi, incluso bloqueado
            try { $tc = New-Object System.Net.Sockets.TcpClient; $tcps.Add($tc); $tareas.Add($tc.ConnectAsync($x, 62078)) } catch {}
        }
        try { [void][System.Threading.Tasks.Task]::WaitAll($tareas.ToArray(), 5000) } catch {}
        foreach ($tc in $tcps) { try { $tc.Close() } catch {} }
    }
    # Bonjour directo a cada dirección (algunos equipos solo responden así)
    $mdTodos = Get-NombresMdns @(1..254 | ForEach-Object { "$pref24.$_" } | Where-Object { $_ -ne $ip.IPAddress })
    $vecinos = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $cfg.InterfaceIndex | Where-Object $filtroV4)
    $gw = [string]($cfg.IPv4DefaultGateway | Select-Object -First 1).NextHop
    $ips = @($vecinos | ForEach-Object { [string]$_.IPAddress })
    # equipos vistos solo por IPv6 (los iPhone suelen estar activos ahí)
    $macsV4 = @($vecinos | ForEach-Object { ([string]$_.LinkLayerAddress).ToUpper() })
    $soloV6 = @(Get-NetNeighbor -AddressFamily IPv6 -InterfaceIndex $cfg.InterfaceIndex | Where-Object {
        ([string]$_.State) -in @('Reachable','Stale','Delay','Probe') -and $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notmatch '^(33-33-|00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)' -and $_.IPAddress -like 'fe80*' -and
        $macsV4 -notcontains ([string]$_.LinkLayerAddress).ToUpper() -and ([string]$_.LinkLayerAddress).ToUpper() -ne ([string]$cfg.NetAdapter.MacAddress).ToUpper() } |
        Group-Object { ([string]$_.LinkLayerAddress).ToUpper() } | ForEach-Object { $_.Group[0] })
    # equipos que respondieron a Bonjour pero no a ARP
    foreach ($kx in @($mdTodos.Keys)) { if (-not $bonjour.ContainsKey($kx)) { $bonjour[$kx] = @{ Nombres = (New-Object System.Collections.Generic.List[string]); Servicios = (New-Object System.Collections.Generic.List[string]); Host = [string]$mdTodos[$kx]; Txt = @{} } } }
    $todosV4 = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $cfg.InterfaceIndex | Where-Object { $_.IPAddress -like "$pref24.*" })
    $script:DiagRed = "Vecinos IPv4 con MAC: $($vecinos.Count) · sin respuesta: $(@($todosV4 | Where-Object { ([string]$_.State) -in @('Unreachable','Incomplete') }).Count) · Bonjour: $($bonjour.Count) · mDNS directo: $($mdTodos.Count) · solo IPv6: $($soloV6.Count) · IPs Bonjour: $((@($bonjour.Keys) | Sort-Object) -join ', ')"
    $soloBonjour = @($bonjour.Keys | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_.StartsWith("$pref24.") -and $ips -notcontains $_ -and $_ -ne $ip.IPAddress })

    Set-Progreso 'Identificando cada dispositivo (nombre, fabricante y tipo)...' 36
    $dnsT = @{}
    foreach ($x in $ips) { try { $dnsT[$x] = [System.Net.Dns]::GetHostEntryAsync($x) } catch {} }
    $nb = Get-NombresNetBios $ips
    $md = Get-NombresMdns $ips
    Set-Progreso 'Revisando qué servicios ofrece cada dispositivo...' 48
    $pa = Get-PuertosAbiertos $ips

    $conocidos = Get-Conocidos
    $marcaBase = Join-Path $Base 'datos\base-dispositivos.ok'
    $hayBase = Test-Path $marcaBase
    $ahora = (Get-Date).ToString('s')
    $consultas = 0
    $lista = New-Object System.Collections.Generic.List[object]

    $macMia = [string]$cfg.NetAdapter.MacAddress
    $todos = @([pscustomobject]@{ IPAddress = $ip.IPAddress; LinkLayerAddress = $macMia; Mia = $true; Via = '' }) +
             @($vecinos | ForEach-Object { [pscustomobject]@{ IPAddress = $_.IPAddress; LinkLayerAddress = [string]$_.LinkLayerAddress; Mia = $false; Via = '' } }) +
             @($soloV6 | ForEach-Object { [pscustomobject]@{ IPAddress = $_.IPAddress; LinkLayerAddress = [string]$_.LinkLayerAddress; Mia = $false; Via = 'IPv6' } }) +
             @($soloBonjour | ForEach-Object { [pscustomobject]@{ IPAddress = $_; LinkLayerAddress = ''; Mia = $false; Via = 'Bonjour' } })
    $nomSvc = @{ '_companion-link._tcp' = 'Apple Continuidad'; '_apple-mobdev2._tcp' = 'Sincronización Apple'; '_rdlink._tcp' = 'Apple'; '_device-info._tcp' = 'Info del equipo'
                 '_airplay._tcp' = 'AirPlay'; '_raop._tcp' = 'AirPlay (audio)'; '_googlecast._tcp' = 'Google Cast'; '_hap._tcp' = 'HomeKit'; '_homekit._tcp' = 'HomeKit'
                 '_spotify-connect._tcp' = 'Spotify Connect'; '_ipp._tcp' = 'Impresión'; '_printer._tcp' = 'Impresión'; '_smb._tcp' = 'Archivos compartidos'
                 '_amzn-wplay._tcp' = 'Amazon'; '_androidtvremote2._tcp' = 'Android TV'; '_sleep-proxy._udp' = 'Proxy de reposo Apple' }
    foreach ($v in $todos) {
        $dip = [string]$v.IPAddress; $mac = ([string]$v.LinkLayerAddress).ToUpper()
        $hostDns = ''
        $t = $dnsT[$dip]
        if ($t -and $t.IsCompleted -and -not $t.IsFaulted) { $hostDns = [string]$t.Result.HostName; if ($hostDns -eq $dip) { $hostDns = '' } }
        $priv = Test-MacPrivada $mac
        $fab = ''
        if (-not $priv) {
            $fab = Get-Fabricante $mac
            if (-not $fab -and $consultas -lt 8) { $consultas++; $fab = Find-FabricanteOnline $mac }
        }
        $s = $ssdp[$dip]
        $bj = $bonjour[$dip]
        $svcBj = ''; $modeloId = ''; $nomBj = ''
        if ($bj) {
            $svcBj = (@($bj.Servicios | ForEach-Object { $t2 = $nomSvc[$_]; if ($t2) { $t2 } else { $_ } }) | Select-Object -Unique) -join ', '
            foreach ($kk in @('model', 'rpmd', 'am', 'md')) { if ($bj.Txt[$kk]) { $modeloId = [string]$bj.Txt[$kk]; break } }
            $nomBj = @($bj.Txt['fn']) + @($bj.Nombres) | Where-Object { $_ } | Select-Object -First 1
            if (-not $nomBj -and $bj.Host) { $nomBj = $bj.Host }
        }
        if ($priv -and -not $fab -and ($svcBj -match 'Apple|AirPlay|HomeKit' -or $modeloId -match '^(iPhone|iPad|Mac|AppleTV|AudioAccessory|Watch)')) { $fab = 'Apple (detectado por Bonjour)' }
        $nombre = ''
        if ($v.Mia) { $nombre = $env:COMPUTERNAME }
        else {
            $cands = @($nomBj, $md[$dip], $nb[$dip], ($hostDns -replace '(?i)\.(home|lan|local|localdomain|router)$', ''))
            $nombre = $cands | Where-Object { $_ -and $_ -notmatch '(?i)^(android|localhost|espressif|esp[-_]?[0-9a-f]*|unknown|desconocido)$' } | Select-Object -First 1
            if (-not $nombre -and $ssdp[$dip] -and $ssdp[$dip].Nombre) { $nombre = '' }
            elseif (-not $nombre) { $nombre = $cands | Where-Object { $_ } | Select-Object -First 1 }
        }
        $puertos = @()
        if ($pa.ContainsKey($dip)) { $puertos = @($pa[$dip] | Sort-Object | ForEach-Object { [pscustomobject]@{ P = [int]$_; Txt = $PuertosSondeo[[int]$_] } }) }
        $modelo = ''
        if ($s) { $modelo = (@($s.Fabricante, $s.Modelo) | Where-Object { $_ }) -join ' ' }
        if (-not $modelo -and $modeloId) { $modelo = Get-NombreApple $modeloId }
        $d = [pscustomobject]@{
            IP = $dip; MAC = $mac; Fabricante = $fab; MacPrivada = $priv; Nombre = [string]$nombre
            NombreUpnp = [string]$s.Nombre; Modelo = $modelo; Servidor = [string]$s.Server; TipoUpnp = [string]$s.TipoUpnp
            Puertos = $puertos; Tipo = ''; Clase = ''; Nota = ''; EsEste = [bool]$v.Mia; EsRouter = ($dip -eq $gw)
            Nuevo = $false; Primera = ''; Apodo = ''; Servicios = $svcBj; ModeloId = $modeloId; Via = [string]$v.Via
        }
        $tt = Get-TipoDispositivo $d $gw
        $d.Clase = $tt[0]; $d.Tipo = $tt[1]
        $notas = @()
        if ($d.EsEste) { $notas += 'Este equipo' }
        if ($d.EsRouter) { $notas += 'Puerta de enlace' }
        if ($priv) { $notas += 'Dirección Wi-Fi privada: el celular inventa una MAC para cada red y así no revela su marca' }
        if ($v.Via -eq 'IPv6') { $notas += 'Visto solo por IPv6 (no respondió por IPv4)' }
        if ($v.Via -eq 'Bonjour') { $notas += 'Respondió por Bonjour pero no a ARP (probablemente en reposo)' }
        $d.Nota = $notas -join ' · '
        $k = $mac
        $e = $null; if ($k) { $e = $conocidos[$k] }
        if ($e) {
            $d.Primera = [string]$e.Primera; $d.Apodo = [string]$e.Apodo
        } else {
            $d.Primera = $ahora; $d.Nuevo = $hayBase -and -not $v.Mia
        }
        if (-not $k) { $d.Nuevo = $false }
        else { $conocidos[$k] = [pscustomobject]@{ Primera = $d.Primera; Ultima = $ahora; Apodo = $d.Apodo; Ip = $dip; Fabricante = $fab; Tipo = $d.Tipo } }
        $lista.Add($d)
    }
    Save-Conocidos $conocidos
    try { [IO.File]::WriteAllText($marcaBase, (Get-Date -Format s)) } catch {}
    $mia = @($lista | Where-Object { $_.EsEste })
    $resto = @($lista | Where-Object { -not $_.EsEste } | Sort-Object { if ($_.IP -match '^\d+\.\d+\.\d+\.\d+$') { [version]$_.IP } else { [version]'999.0.0.0' } })
    return @($mia + $resto)
}

# ------------------------------------------------------------ conexiones ----
function Get-AnalisisConexiones {
    $procs = @{}
    foreach ($p in Get-CimInstance Win32_Process) { $procs[[int]$p.ProcessId] = $p }
    $res = New-Object System.Collections.Generic.List[object]
    $tcp = Get-NetTCPConnection | Where-Object { ([string]$_.State) -in @('Established','Listen','SynSent','CloseWait') }
    foreach ($c in $tcp) {
        $pidc = [int]$c.OwningProcess
        if ($pidc -eq $PID -or $pidc -eq 0) { continue }
        $p = $procs[$pidc]
        if ($p -and $p.CommandLine -and ([string]$p.CommandLine -match $PatronPropio)) { continue }
        $proc = '?'; $ruta = $null
        if ($p) { $proc = $p.Name; $ruta = $p.ExecutablePath } elseif ($pidc -eq 4) { $proc = 'System' }
        $n = [IO.Path]::GetFileNameWithoutExtension([string]$proc).ToLower()
        $estado = [string]$c.State
        $remota = [string]$c.RemoteAddress; $rport = [int]$c.RemotePort; $lport = [int]$c.LocalPort
        $esEscucha = $estado -eq 'Listen'
        $externa = (-not $esEscucha) -and -not (Test-Loopback $remota) -and ($remota -notin @('0.0.0.0','::'))
        $expuesta = $esEscucha -and -not (Test-Loopback $c.LocalAddress)

        $puntos = 0
        $motivos = New-Object System.Collections.Generic.List[string]

        if ($externa -and $PuertosAltoRiesgo.ContainsKey($rport)) {
            $puntos += 4; $motivos.Add("Conectado al puerto remoto $rport ($($PuertosAltoRiesgo[$rport]))")
        }
        if (($expuesta -or $externa) -and $PuertosAltoRiesgo.ContainsKey($lport)) {
            $puntos += 4; $motivos.Add("Usa el puerto local $lport ($($PuertosAltoRiesgo[$lport]))")
        }
        if (($expuesta -or $externa) -and $PuertosAccesoRemoto.ContainsKey($lport)) {
            $puntos += 2; $motivos.Add("Acepta conexiones de acceso remoto en el puerto $lport ($($PuertosAccesoRemoto[$lport]))")
        }
        if ($externa -and $PuertosAccesoRemoto.ContainsKey($rport)) {
            $puntos += 1; $motivos.Add("Conexión de control remoto activa ($($PuertosAccesoRemoto[$rport]))")
        }

        if (($externa -or $expuesta) -and $pidc -ne 4) {
            if ($ruta) {
                $rl = $ruta.ToLower()
                $enWindows = $rl.StartsWith(([string]$env:windir).ToLower() + '\')
                $f = Get-Firma $ruta
                if ($rl -match $CarpetasRaras) {
                    $puntos += 2; $motivos.Add('Se ejecuta desde una carpeta inusual')
                }
                if ($f -and $f.Estado -in @('NotSigned','HashMismatch','NotTrusted','Incompatible')) {
                    $puntos += 2; $motivos.Add("Ejecutable sin firma digital válida ($($f.Estado))")
                }
                if ($NombresSistema -contains $n -and -not $enWindows) {
                    $puntos += 4; $motivos.Add("Se hace pasar por un proceso de Windows ($proc) pero está fuera de C:\Windows")
                }
                if ($n -match $NombresSenuelo -and -not ($f -and $f.Estado -eq 'Valid' -and $f.Firmante -match 'Microsoft')) {
                    $puntos += 3; $motivos.Add("Nombre que imita un archivo del sistema ('$proc')")
                }
            }
            if ($externa -and $Shells -contains $n) {
                $puntos += 3; $motivos.Add("Una consola/intérprete ($proc) tiene una conexión de red abierta: típico de una 'reverse shell'")
            }
        }

        $rem = '-'
        if (-not $esEscucha) { $rem = "${remota}:$rport" }
        $nivel = Get-Nivel $puntos
        $res.Add([pscustomobject]@{
            Nivel = $nivel; Color = $ColorNivel[$nivel]; Puntos = $puntos
            Proceso = $proc; PID = $pidc; Estado = $estado
            Local = "$($c.LocalAddress):$lport"; Remota = $rem; IpRemota = $remota
            Ruta = $ruta; Motivos = ($motivos -join ' | ')
            Externa = $externa; Expuesta = $expuesta; Escucha = $esEscucha
        })
    }
    return $res
}

# ------------------------------------------------ detalles de conexiones ----
$script:CacheProg = @{}
$script:CacheIp = @{}
$script:MapaServ = $null; $script:MapaServHora = [datetime]::MinValue

function Get-InfoPrograma($ruta) {
    if (-not $ruta) { return $null }
    if ($script:CacheProg.ContainsKey($ruta)) { return $script:CacheProg[$ruta] }
    $vi = $null
    try { $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ruta) } catch {}
    $o = [pscustomobject]@{ Descripcion = ([string]$vi.FileDescription).Trim(); Empresa = ([string]$vi.CompanyName).Trim() }
    $script:CacheProg[$ruta] = $o
    return $o
}
function Get-MapaServicios {
    if ($script:MapaServ -and ((Get-Date) - $script:MapaServHora).TotalSeconds -lt 60) { return $script:MapaServ }
    $m = @{}
    foreach ($s in (Get-CimInstance Win32_Service -Filter "State='Running'")) {
        $k = [int]$s.ProcessId
        if ($k) { if (-not $m.ContainsKey($k)) { $m[$k] = New-Object System.Collections.Generic.List[string] }; $m[$k].Add([string]$s.DisplayName) }
    }
    $script:MapaServ = $m; $script:MapaServHora = Get-Date
    return $m
}
function Test-IpPublica($ip) {
    $ip = [string]$ip
    if (-not $ip -or $ip -notmatch '[.:]') { return $false }
    return ($ip -notmatch '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|::$|fe80:|f[cd][0-9a-f]{2}:|ff)')
}
function Update-InfoIps($ips) {
    $nuevas = @($ips | Where-Object { (Test-IpPublica $_) -and -not $script:CacheIp.ContainsKey([string]$_) } | Select-Object -Unique | Select-Object -First 100)
    if (-not $nuevas.Count) { return }
    $dns = @{}
    foreach ($x in $nuevas) { try { $dns[$x] = [System.Net.Dns]::GetHostEntryAsync($x) } catch {} }
    $geo = @{}
    $body = '[' + (($nuevas | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
    foreach ($intento in 1..2) {
        if ($geo.Count) { break }
        try {
            $r = Invoke-RestMethod -Method Post -Uri 'http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,as,query&lang=es' `
                 -Body $body -ContentType 'application/json' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            foreach ($g in @($r)) { if ($g.status -eq 'success') { $geo[[string]$g.query] = $g } }
        } catch {}
    }
    $faltan = @($nuevas | Where-Object { -not $geo.ContainsKey([string]$_) } | Select-Object -First 40)
    if ($faltan.Count) {
        # segunda fuente: ipinfo.io, todas las consultas en paralelo
        try {
            Add-Type -AssemblyName System.Net.Http
            $hc = New-Object System.Net.Http.HttpClient
            $hc.Timeout = [TimeSpan]::FromSeconds(6)
            $tq = @{}
            foreach ($x in $faltan) { $tq[$x] = $hc.GetStringAsync("https://ipinfo.io/$x/json") }
            try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tq.Values), 7000) } catch {}
            foreach ($x in $faltan) {
                $t = $tq[$x]
                if ([string]$t.Status -eq 'RanToCompletion') {
                    $o = $t.Result | ConvertFrom-Json
                    if ($o.ip) { $geo[$x] = [pscustomobject]@{ country = [string]$o.country; countryCode = [string]$o.country; city = [string]$o.city; org = [string]$o.org; isp = ''; hostname = [string]$o.hostname } }
                }
            }
            $hc.Dispose()
        } catch {}
    }
    $fin = (Get-Date).AddMilliseconds(1500)
    while ((Get-Date) -lt $fin -and @($dns.Values | Where-Object { -not $_.IsCompleted }).Count) { Start-Sleep -Milliseconds 100 }
    foreach ($x in $nuevas) {
        $h = ''
        $t = $dns[$x]
        if ($t -and $t.IsCompleted -and -not $t.IsFaulted) { $h = [string]$t.Result.HostName; if ($h -eq $x) { $h = '' } }
        $g = $geo[$x]
        $org = ''
        if ($g) { $org = [string]$g.org; if (-not $org) { $org = [string]$g.isp }; if (-not $h -and $g.hostname) { $h = [string]$g.hostname } }
        if (-not $g -and -not $h) { continue }   # sin datos: se reintenta en la próxima vuelta
        $script:CacheIp[$x] = [pscustomobject]@{ Host = $h; Org = $org; Pais = [string]$g.country; Cc = [string]$g.countryCode; Ciudad = [string]$g.city }
    }
}
function Get-NombreServicio($h, $org) {
    $t = ("$h $org").ToLower()
    $mapa = [ordered]@{
        '1e100\.net|google|youtube|gvt1|googleusercontent' = 'Google'
        'whatsapp' = 'WhatsApp (Meta)'
        'fbcdn|facebook|instagram|meta platforms' = 'Meta (Facebook / Instagram)'
        'msedge\.net|microsoft|azure|windows\.com|live\.com|office|skype|bing|msn|xbox' = 'Microsoft'
        'amazonaws|aws|amazon' = 'Amazon / AWS'
        'akamai' = 'Akamai (red de contenidos)'
        'cloudflare' = 'Cloudflare'
        'apple|icloud|aaplimg' = 'Apple'
        'spotify' = 'Spotify'
        'netflix|nflx' = 'Netflix'
        'valve|steam' = 'Steam (Valve)'
        'discord' = 'Discord'
        'zoom' = 'Zoom'
        'tiktok|bytedance' = 'TikTok (ByteDance)'
        'anthropic' = 'Anthropic (Claude)'
        'openai' = 'OpenAI'
        'github' = 'GitHub'
        'fastly' = 'Fastly (red de contenidos)'
        'edgecast|edgio|verizon digital' = 'Edgio (red de contenidos)'
        'dropbox' = 'Dropbox'
        'entel' = 'Entel'
        'movistar|telefonica' = 'Movistar'
        'vtr' = 'VTR'
        'claro' = 'Claro'
    }
    foreach ($k in $mapa.Keys) { if ($t -match $k) { return $mapa[$k] } }
    if ($org) { return (([string]$org -replace '(?i)^AS\d+\s+', '') -replace '(?i)[,\s]+(inc\.?|llc|ltd\.?|s\.a\.?|corporation|corp\.?)$', '').Trim() }
    if ($h) { $p = $h.Split('.'); if ($p.Count -ge 2) { return ($p[-2..-1] -join '.') } }
    return ''
}
function Get-InfoPuertoLocal($puerto, $proc, $servicios) {
    $puerto = [int]$puerto
    $n = ([IO.Path]::GetFileNameWithoutExtension([string]$proc)).ToLower()
    if ($PuertosLocales.ContainsKey($puerto)) { $x = $PuertosLocales[$puerto]; return @($x[0], $x[1], $x[2]) }
    if ($puerto -ge 49152 -and $n -in @('lsass','wininit','services','spoolsv','svchost')) {
        $quien = $proc; if ($servicios) { $quien = $servicios }
        return @('RPC dinámico de Windows', "Puerto que Windows asigna a un servicio del sistema ($quien). Es normal.", 'Normal')
    }
    if ($n -eq 'system') { return @('Servicio del sistema', 'Lo abrió el núcleo de Windows (por ejemplo, para compartir archivos o descubrir equipos).', 'Normal') }
    $txt = "Lo abrió $proc para recibir conexiones desde la red."
    if ($servicios) { $txt = "Lo abrió $proc ($servicios) para recibir conexiones desde la red." }
    return @("Puerto $puerto", $txt, 'Depende')
}
function Add-InfoConexiones($conns, $disp, [switch]$SinConsultar) {
    $serv = Get-MapaServicios
    if (-not $SinConsultar) { Update-InfoIps @($conns | Where-Object { $_.Externa } | ForEach-Object { $_.IpRemota }) }
    $porIp = @{}
    foreach ($d in @($disp)) { if ($d) { $porIp[[string]$d.IP] = $d } }
    foreach ($c in $conns) {
        $pi = Get-InfoPrograma $c.Ruta
        $desc = ''; $emp = ''
        if ($pi) { $desc = $pi.Descripcion; $emp = $pi.Empresa }
        $svc = ''
        if ($serv.ContainsKey([int]$c.PID)) { $svc = ($serv[[int]$c.PID] | Select-Object -First 3) -join ', ' }
        $destino = ''; $donde = ''; $hostR = ''; $org = ''; $cc = ''
        if ($c.Externa) {
            $i = $script:CacheIp[[string]$c.IpRemota]
            if ($i) { $hostR = $i.Host; $org = $i.Org; $cc = $i.Cc; $destino = Get-NombreServicio $i.Host $i.Org; $donde = (@($i.Ciudad, $i.Pais) | Where-Object { $_ }) -join ', ' }
            elseif ($porIp.ContainsKey([string]$c.IpRemota)) { $destino = 'Equipo de tu red: ' + (Get-DescDisp $porIp[[string]$c.IpRemota]); $donde = 'Tu red local' }
            elseif (-not (Test-IpPublica $c.IpRemota)) { $destino = 'Dirección de tu red local'; $donde = 'Tu red local' }
        }
        $rp = 0
        if ($c.Remota -match ':(\d+)$') { $rp = [int]$matches[1] }
        $servicio = ''; $explic = ''; $normal = ''; $alcance = ''
        if ($c.Escucha) {
            $lp = 0; if ($c.Local -match ':(\d+)$') { $lp = [int]$matches[1] }
            $ip = Get-InfoPuertoLocal $lp $c.Proceso $svc
            $servicio = $ip[0]; $explic = $ip[1]; $normal = $ip[2]
            $la = ($c.Local -replace ':\d+$', '')
            if ($la -in @('0.0.0.0', '::', '[::]')) { $alcance = 'Toda la red' } else { $alcance = "Solo la red de $la" }
        } elseif ($ServiciosRemotos.ContainsKey($rp)) { $servicio = $ServiciosRemotos[$rp] }
        elseif ($rp) { $servicio = "Puerto $rp" }
        $estTxt = $EstadosTxt[[string]$c.Estado]; if (-not $estTxt) { $estTxt = [string]$c.Estado }
        $c | Add-Member -Force -NotePropertyMembers @{
            Programa = $desc; Empresa = $emp; Servicios = $svc; Destino = $destino; Host = $hostR; Org = $org; Cc = $cc
            Donde = $donde; Servicio = $servicio; Explicacion = $explic; Normal = $normal; Alcance = $alcance; EstadoTxt = $estTxt
        }
    }
}

# ----------------------------------------------- puntaje y recomendaciones --
function Get-Puntaje($hall) {
    $p = 100
    foreach ($x in @($hall)) { switch ($x.Nivel) { 'ALTO' { $p -= 25 } 'MEDIO' { $p -= 10 } 'BAJO' { $p -= 3 } } }
    return [Math]::Max(0, $p)
}
function Get-Calificacion($p) {
    if ($p -ge 90) { return 'Excelente' } elseif ($p -ge 75) { return 'Buena' } elseif ($p -ge 50) { return 'Mejorable' } else { return 'En riesgo' }
}
function Get-Consejos($r) {
    $l = New-Object System.Collections.Generic.List[object]
    function Add-Rec($e, $t, $d) { $l.Add([pscustomobject]@{ Estado = $e; Titulo = $t; Texto = $d }) }
    $w = $r.Wifi
    if ($w) {
        if ($w.Seguridad -match 'Abierta|Open|WEP') { Add-Rec 'mejorar' 'Tu Wi-Fi no está bien protegido' "La red '$($w.SSID)' usa $($w.Seguridad). Configura el router con WPA2 o WPA3 y una contraseña de al menos 12 caracteres." }
        elseif ($w.Seguridad -match 'WPA3') { Add-Rec 'ok' 'Wi-Fi con WPA3' "Tu red '$($w.SSID)' usa el cifrado más moderno. Mantén una contraseña larga." }
        elseif ($w.Seguridad -match 'WPA2') { Add-Rec 'ok' 'Wi-Fi con WPA2' "Tu red '$($w.SSID)' está cifrada ($($w.Seguridad), $($w.Cifrado)). Es seguro con una contraseña larga; si tu router ofrece WPA3 o «WPA2/WPA3», actívalo." }
        else { Add-Rec 'mejorar' 'Cifrado Wi-Fi antiguo' "La red usa $($w.Seguridad). Cámbiala a WPA2 o WPA3 en el router." }
    }
    $rt = @($r.Disp | Where-Object { $_.EsRouter }) | Select-Object -First 1
    if ($r.Gw) {
        $fabR = ''; if ($rt -and $rt.Fabricante) { $fabR = " (fabricante: $($rt.Fabricante))" }
        Add-Rec 'info' 'Revisa tu router' "Entra a http://$($r.Gw)$fabR y cambia la contraseña de administración si sigue siendo la de fábrica (no es la misma del Wi-Fi). Desactiva WPS y actualiza su firmware."
    }
    $intel = @($r.Disp | Where-Object { $_.Clase -in @('iot','altavoz','streaming','tv','clima','camara') })
    if ($intel.Count) {
        $marcas = (@($intel | ForEach-Object { $_.Fabricante } | Where-Object { $_ } | Select-Object -Unique) | Select-Object -First 4) -join ', '
        Add-Rec 'info' "Tienes $($intel.Count) aparato(s) inteligente(s)" "Parlantes, TV, enchufes o electrodomésticos ($marcas). Si tu router tiene «red de invitados», conéctalos ahí para separarlos de tu PC y celulares, y mantén sus apps actualizadas."
    }
    $desc = @($r.Disp | Where-Object { $_.Clase -eq 'desconocido' -and -not $_.Apodo })
    $nuevos = @($r.Disp | Where-Object { $_.Nuevo })
    if ($nuevos.Count) { Add-Rec 'mejorar' "$($nuevos.Count) dispositivo(s) nuevo(s) en tu red" 'Aparecieron desde el último escaneo. Revisa la pestaña Dispositivos; si no los reconoces, cambia la contraseña del Wi-Fi.' }
    elseif ($desc.Count) { Add-Rec 'info' "$($desc.Count) dispositivo(s) sin identificar" 'Revisa la pestaña Dispositivos y ponles un apodo a los que reconozcas. Así RedGuard te avisará solo de los realmente nuevos.' }
    else { Add-Rec 'ok' 'Dispositivos identificados' 'Todos los equipos de tu red tienen un tipo o un apodo.' }
    $priv = @($r.Disp | Where-Object { $_.MacPrivada })
    if ($priv.Count) {
        $apple = @($priv | Where-Object { $_.Fabricante -like 'Apple*' }).Count
        $txtA = ''; if ($apple) { $txtA = " ($apple identificados como Apple por Bonjour)" }
        Add-Rec 'info' "$($priv.Count) dispositivo(s) usan dirección Wi-Fi privada$txtA" 'Es una función de privacidad de iPhone y Android: la MAC cambia por red y no revela la marca. No es un riesgo. En tu red de casa déjala en «Fija» (iPhone: Ajustes > Wi-Fi > (i) > Dirección Wi-Fi privada) para que RedGuard los reconozca siempre; con «Rotativa» aparecerán como dispositivos nuevos cada cierto tiempo.'
    }
    if ($r.AvNivel -eq 'OK') { Add-Rec 'ok' 'Antivirus activo' 'Microsoft Defender protege en tiempo real.' } else { Add-Rec 'mejorar' 'Antivirus' "Microsoft Defender: $($r.AvTxt). Actívalo en Seguridad de Windows." }
    if ($r.FwNivel -eq 'OK') { Add-Rec 'ok' 'Firewall activo' 'El firewall de Windows está encendido en todos los perfiles.' } else { Add-Rec 'mejorar' 'Firewall' $r.FwTxt }
    if ($null -ne $r.ParcheDias) {
        if ($r.ParcheDias -le 45) { Add-Rec 'ok' 'Windows actualizado' "La última actualización se instaló hace $($r.ParcheDias) día(s)." }
        else { Add-Rec 'mejorar' 'Windows sin actualizaciones recientes' "La última actualización se instaló hace $($r.ParcheDias) días. Ve a Configuración > Windows Update." }
    }
    if ($r.Rdp) { Add-Rec 'mejorar' 'Escritorio remoto activado' 'Si no lo usas, desactívalo en Configuración > Sistema > Escritorio remoto.' } else { Add-Rec 'ok' 'Escritorio remoto apagado' 'Nadie puede controlar este PC por RDP.' }
    $sos = @($r.Conns | Where-Object { $_.Nivel -in @('ALTO','MEDIO') })
    if ($sos.Count) { Add-Rec 'mejorar' 'Conexiones sospechosas' "Hay $($sos.Count) conexión(es) que revisar en la pestaña Conexiones." } else { Add-Rec 'ok' 'Sin conexiones sospechosas' 'Ningún programa usa puertos de hackers ni se hace pasar por Windows.' }
    if ($r.Perfil -eq 'Pública' -and -not $r.Vpn) { Add-Rec 'info' 'Red marcada como Pública' 'Windows te protege más en esta red. Si es tu casa puedes dejarla así; en cafés y aeropuertos usa una VPN o los datos del celular.' }
    return $l.ToArray()
}

# --------------------------------------------------- revisión (solo datos) --
function Get-Revision {
    $script:Hallazgos = New-Object System.Collections.Generic.List[object]
    $inicio = Get-Date

    # --- Red ---
    Set-Progreso 'Leyendo tu conexión de red...' 5
    $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
    $wifi = Get-InfoWifi
    $perfil = $null; $ipLocal = ''; $gw = ''; $dnsSrv = ''; $adaptador = ''
    if ($cfg) {
        $perfil    = Get-NetConnectionProfile -InterfaceIndex $cfg.InterfaceIndex | Select-Object -First 1
        $ip4       = $cfg.IPv4Address | Select-Object -First 1
        $ipLocal   = "$($ip4.IPAddress)/$($ip4.PrefixLength)"
        $gw        = [string]($cfg.IPv4DefaultGateway | Select-Object -First 1).NextHop
        $dnsSrv    = ((Get-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4).ServerAddresses) -join ', '
        $adaptador = "$($cfg.InterfaceAlias) ($($cfg.NetAdapter.InterfaceDescription))"
    }
    $cat = [string]$perfil.NetworkCategory
    $catTxt = $cat
    if ($cat -eq 'Public') { $catTxt = 'Pública' } elseif ($cat -eq 'Private') { $catTxt = 'Privada' } elseif ($cat -eq 'DomainAuthenticated') { $catTxt = 'Dominio' }

    Set-Progreso 'Consultando tu IP pública y ubicación...' 15
    $pub = Get-IpPublica
    $vpn = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'VPN|TAP-|WireGuard|Tunnel|OpenVPN|Fortinet|AnyConnect|NordLynx|ProtonVPN|Tailscale|ZeroTier' })
    $vpnTxt = ''
    if ($vpn.Count) { $vpnTxt = ($vpn | ForEach-Object { $_.InterfaceDescription }) -join ', ' }

    $segNivel = 'OK'
    if (-not $cfg) {
        Add-Hallazgo 'INFO' 'Sin conexión de red' 'No se encontró un adaptador conectado con puerta de enlace.' 'Conéctate a una red y vuelve a escanear.'
    } elseif ($wifi) {
        if ($wifi.Seguridad -match 'Abierta|Open') {
            $segNivel = 'ALTO'
            Add-Hallazgo 'ALTO' "Wi-Fi abierta: '$($wifi.SSID)'" 'La red no tiene contraseña; cualquiera cerca puede ver o manipular tu tráfico no cifrado.' 'Evita entrar a bancos o cuentas importantes aquí, o usa una VPN. Prefiere los datos del celular.'
        } elseif ($wifi.Seguridad -match 'WEP') {
            $segNivel = 'ALTO'
            Add-Hallazgo 'ALTO' "Wi-Fi con cifrado WEP: '$($wifi.SSID)'" 'WEP se rompe en minutos.' 'Configura el router con WPA2 o WPA3.'
        } elseif ($wifi.Seguridad -notmatch 'WPA2|WPA3') {
            $segNivel = 'MEDIO'
            Add-Hallazgo 'MEDIO' "Seguridad Wi-Fi débil: $($wifi.Seguridad)" 'WPA (versión 1) tiene fallas conocidas.' 'Configura el router con WPA2 o WPA3.'
        }
        if ($cat -eq 'Private' -and $wifi.Seguridad -match 'Abierta|Open') {
            Add-Hallazgo 'MEDIO' 'Red abierta marcada como Privada' 'Windows comparte más cosas en redes privadas.' 'Configuración > Red e Internet > Wi-Fi > esta red > Tipo de perfil: Pública.'
        }
    }

    # --- Dispositivos ---
    $disp = @()
    if ($cfg) {
        Set-Progreso 'Buscando dispositivos en tu red...' 30
        $disp = @(Get-DispositivosRed $cfg)
        $macGw = ($disp | Where-Object { $_.IP -eq $gw } | Select-Object -First 1).MAC
        if ($macGw) {
            $clones = @($disp | Where-Object { $_.MAC -eq $macGw -and $_.IP -ne $gw })
            if ($clones.Count) {
                Add-Hallazgo 'ALTO' 'Posible suplantación del router (ARP spoofing)' ("La MAC del router ($macGw) también la usa: " + (($clones | ForEach-Object { $_.IP }) -join ', ') + '. Alguien podría estar interceptando tu tráfico (man-in-the-middle).') 'Desconéctate de esta red, reinicia el router y vuelve a escanear. Si persiste, cambia la contraseña del Wi-Fi.'
            }
        }
    }

    foreach ($d in @($disp | Where-Object { $_.Nuevo })) {
        Add-Hallazgo 'BAJO' "Dispositivo nuevo en tu red: $(Get-DescDisp $d)" "IP: $($d.IP)`nMAC: $($d.MAC)" 'Si no lo reconoces, cambia la contraseña de tu Wi-Fi. Si es tuyo, ponle un apodo en la pestaña Dispositivos.'
    }
    foreach ($d in @($disp | Where-Object { -not $_.EsEste })) {
        $pp = @($d.Puertos | ForEach-Object { [int]$_.P })
        if ($pp -contains 23) { Add-Hallazgo 'MEDIO' "Telnet abierto en $(Get-DescDisp $d)" "IP: $($d.IP). Telnet permite entrar al equipo sin cifrar; lo usan botnets como Mirai para tomar control de routers y cámaras." 'Desactiva Telnet en la configuración de ese equipo y cambia su contraseña si sigue la de fábrica.' }
        if ($pp -contains 5555) { Add-Hallazgo 'MEDIO' "Depuración de Android abierta en $(Get-DescDisp $d)" "IP: $($d.IP). El puerto 5555 (ADB) permite controlar ese dispositivo desde la red." 'En ese Android o TV, desactiva Opciones de desarrollador > Depuración por red (ADB).' }
    }

    # --- Conexiones ---
    Set-Progreso 'Analizando conexiones y programas...' 60
    $conns = @(Get-AnalisisConexiones)
    Set-Progreso 'Averiguando a dónde se conecta cada programa...' 68
    Add-InfoConexiones $conns $disp
    $sosp = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($conns | Where-Object { $_.Nivel -in @('ALTO','MEDIO') } | Group-Object PID)) {
        $top = $g.Group | Sort-Object Puntos -Descending | Select-Object -First 1
        $rem = @($g.Group | Where-Object { -not $_.Escucha } | ForEach-Object { $_.Remota } | Select-Object -Unique)
        $loc = @($g.Group | Where-Object { $_.Escucha } | ForEach-Object { $_.Local } | Select-Object -Unique)
        $mot = @($g.Group | ForEach-Object { $_.Motivos -split ' \| ' } | Where-Object { $_ } | Select-Object -Unique)
        $hostRem = ''
        $ipTop = ($g.Group | Where-Object { $_.Externa } | Select-Object -First 1).IpRemota
        if ($ipTop) { $rr = Resolve-DnsName -Name $ipTop -Type PTR -QuickTimeout -DnsOnly | Select-Object -First 1; if ($rr.NameHost) { $hostRem = " ($($rr.NameHost))" } }
        $det = "Programa: $($top.Proceso)  (PID $($top.PID))"
        if ($top.Ruta) { $det += "`nArchivo: $($top.Ruta)" }
        if ($rem.Count) { $det += "`nConectado a: " + ($rem -join ', ') + $hostRem }
        if ($top.Destino) { $det += "`nDestino: $($top.Destino) $($top.Donde)" }
        if ($top.Programa -or $top.Empresa) { $det += "`nDescripción: $($top.Programa) $($top.Empresa)" }
        if ($loc.Count) { $det += "`nEscuchando en: " + ($loc -join ', ') }
        $det += "`nPor qué: " + ($mot -join '; ')
        Add-Hallazgo $top.Nivel "Conexión sospechosa: $($top.Proceso)" $det 'Si no reconoces este programa: ciérralo, desconéctate de Internet y ejecuta un análisis completo de Microsoft Defender.'
        $sosp.Add([pscustomobject]@{ Nivel = $top.Nivel; Proceso = $top.Proceso; PID = $top.PID; Ruta = $top.Ruta })
    }

    # --- Protección ---
    Set-Progreso 'Revisando Defender, firewall y configuración...' 85
    $mp = Get-MpComputerStatus
    $avTxt = 'No disponible'; $avNivel = 'MEDIO'; $edad = $null
    if ($mp) {
        $okAv = $mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled
        if ($okAv) { $avTxt = 'Activo (tiempo real)'; $avNivel = 'OK' }
        elseif ($mp.AntivirusEnabled) { $avTxt = 'Sin protección en tiempo real'; $avNivel = 'ALTO' }
        else { $avTxt = 'Desactivado'; $avNivel = 'ALTO' }
        if ($mp.AntivirusSignatureLastUpdated) { $edad = [int]((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays }
        if (-not $okAv) { Add-Hallazgo 'ALTO' 'Microsoft Defender no protege en tiempo real' 'El antivirus de Windows está apagado o parcialmente desactivado.' 'Abre Seguridad de Windows > Protección contra virus y amenazas y actívalo.' }
        if ($edad -gt 7) { Add-Hallazgo 'MEDIO' 'Firmas del antivirus desactualizadas' "Última actualización hace $edad días." 'Seguridad de Windows > Protección contra virus y amenazas > Buscar actualizaciones.' }
    }
    $fwOff = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
    $fwTxt = 'Activo'; $fwNivel = 'OK'
    if ($fwOff.Count) {
        $fwTxt = 'Apagado en: ' + (($fwOff | ForEach-Object { $_.Name }) -join ', '); $fwNivel = 'ALTO'
        Add-Hallazgo 'ALTO' 'Firewall de Windows apagado' $fwTxt 'Seguridad de Windows > Firewall y protección de red > actívalo en todos los perfiles.'
    }
    $rdpOn = ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
    if ($rdpOn) { Add-Hallazgo 'MEDIO' 'Escritorio remoto activado' 'Otros equipos pueden intentar entrar a este por RDP (puerto 3389).' 'Si no lo usas: Configuración > Sistema > Escritorio remoto > Desactivado.' }
    $px = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxy = ''
    if ($px.ProxyEnable -eq 1 -and $px.ProxyServer) {
        $proxy = [string]$px.ProxyServer
        Add-Hallazgo 'MEDIO' "Proxy configurado: $proxy" 'Todo tu tráfico web pasa por ese servidor. Algunos malware lo configuran para espiar.' 'Si no lo configuraste tú: Configuración > Red e Internet > Proxy > desactívalo.'
    }
    $hosts = @(Get-Content -Encoding UTF8 "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' })
    if ($hosts.Count) { Add-Hallazgo 'BAJO' 'El archivo hosts tiene entradas' (($hosts | Select-Object -First 8) -join "`n") 'Revísalas: el malware a veces redirige bancos o bloquea antivirus desde aquí.' }

    $parche = $null
    try {
        $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $parche = [int]((Get-Date) - [datetime]$hf.InstalledOn).TotalDays }
    } catch {}
    if ($null -ne $parche -and $parche -gt 60) { Add-Hallazgo 'MEDIO' 'Windows lleva tiempo sin actualizarse' "La última actualización instalada es de hace $parche días." 'Ve a Configuración > Windows Update e instala las actualizaciones pendientes.' }

    $hall = @($script:Hallazgos | Sort-Object { $OrdenNivel[$_.Nivel] })
    $nAlto = @($hall | Where-Object { $_.Nivel -eq 'ALTO' }).Count
    $nMed  = @($hall | Where-Object { $_.Nivel -eq 'MEDIO' }).Count

    # Se arma campo por campo: si un valor falla, el resto del resultado sigue intacto.
    $h = [ordered]@{}
    $h.Inicio = $inicio;   $h.Equipo = $env:COMPUTERNAME; $h.Cfg = $cfg;        $h.Wifi = $wifi
    $h.SegNivel = $segNivel; $h.Perfil = $catTxt;        $h.IpLocal = $ipLocal; $h.Gw = $gw
    $h.Dns = $dnsSrv;      $h.Adaptador = $adaptador;    $h.Pub = $pub;         $h.Vpn = $vpnTxt
    $h.Disp = @($disp);    $h.Conns = @($conns);         $h.Sosp = $sosp.ToArray()
    $h.Mp = $mp;           $h.AvTxt = $avTxt;            $h.AvNivel = $avNivel; $h.FirmasDias = $edad
    $h.FwTxt = $fwTxt;     $h.FwNivel = $fwNivel;        $h.Rdp = [bool]$rdpOn; $h.Proxy = $proxy
    $h.Hosts = @($hosts).Count; $h.Hallazgos = @($hall); $h.NAlto = $nAlto; $h.NMed = $nMed; $h.Archivo = ''
    $h.ParcheDias = $parche; $h.Puntaje = Get-Puntaje $hall; $h.Calificacion = Get-Calificacion $h.Puntaje
    $r = New-Object PSObject -Property $h
    $r | Add-Member -Force -NotePropertyName Consejos -NotePropertyValue @(Get-Consejos $r)

    Set-Progreso 'Generando el reporte...' 95
    $archivo = Join-Path $DirReportes ('RedGuard_' + $inicio.ToString('yyyy-MM-dd_HH-mm-ss') + '.html')
    [IO.File]::WriteAllText($archivo, (New-Reporte $r), (New-Object System.Text.UTF8Encoding $true))
    $r.Archivo = $archivo
    return $r
}

# ------------------------------------------------------- revisión consola ---
function Invoke-Revision {
    Clear-Host
    Write-Host ''
    Write-Host '   ____          _  ____                     _ ' -ForegroundColor Cyan
    Write-Host '  |  _ \ ___  __| |/ ___|_   _  __ _ _ __ __| |' -ForegroundColor Cyan
    Write-Host '  | |_) / _ \/ _` | |  _| | | |/ _` | ''__/ _` |' -ForegroundColor Cyan
    Write-Host '  |  _ <  __/ (_| | |_| | |_| | (_| | | | (_| |' -ForegroundColor Cyan
    Write-Host '  |_| \_\___|\__,_|\____|\__,_|\__,_|_|  \__,_|' -ForegroundColor Cyan
    Write-Host "   Guardián de red v$Version  -  $((Get-Date).ToString('dd-MM-yyyy HH:mm'))" -ForegroundColor DarkCyan
    Write-Host ''

    $r = Get-Revision

    Write-Titulo 'TU RED'
    if ($r.Wifi) {
        Write-Dato 'Wi-Fi (SSID)' $r.Wifi.SSID
        Write-Dato 'Seguridad' "$($r.Wifi.Seguridad) / $($r.Wifi.Cifrado)" (Get-Color $r.SegNivel)
        Write-Dato 'Señal' "$($r.Wifi.Senal)   $($r.Wifi.Radio) $($r.Wifi.Banda) canal $($r.Wifi.Canal)"
    } elseif ($r.Cfg) { Write-Dato 'Tipo' 'Cable / otra conexión' }
    Write-Dato 'Perfil de red' $r.Perfil
    Write-Dato 'IP local' $r.IpLocal
    Write-Dato 'Puerta de enlace' $r.Gw
    Write-Dato 'Servidores DNS' $r.Dns
    if ($r.Pub) {
        Write-Dato 'IP pública' $r.Pub.IP
        Write-Dato 'Ubicación aprox.' "$($r.Pub.Ciudad), $($r.Pub.Region), $($r.Pub.Pais)"
        Write-Dato 'Proveedor' $r.Pub.Proveedor
    }
    if ($r.Vpn) { Write-Dato 'VPN activa' $r.Vpn 'Green' }

    Write-Titulo "DISPOSITIVOS EN TU RED ($(@($r.Disp).Count))"
    foreach ($d in $r.Disp) {
        $col = 'White'; if ($d.Nota -eq 'Este equipo') { $col = 'Cyan' } elseif ($d.Nota -like 'Router*') { $col = 'Green' }
        $nom = [string]$d.Nombre; if ($nom.Length -gt 28) { $nom = $nom.Substring(0, 28) }
        Write-Host ('  {0,-16} {1,-18} {2,-28} {3}' -f $d.IP, $d.MAC, $nom, "$($d.Tipo) · $($d.Fabricante)") -ForegroundColor $col
    }

    Write-Titulo 'CONEXIONES Y PROGRAMAS'
    Write-Dato 'Conexiones activas' "$(@($r.Conns | Where-Object { $_.Externa -and $_.Estado -eq 'Established' }).Count) hacia fuera del equipo"
    Write-Dato 'Puertos abiertos' "$(@($r.Conns | Where-Object { $_.Expuesta }).Count) esperando conexiones"

    Write-Titulo 'PROTECCIÓN'
    Write-Dato 'Microsoft Defender' $r.AvTxt (Get-Color $r.AvNivel)
    Write-Dato 'Firewall' $r.FwTxt (Get-Color $r.FwNivel)
    $rdpTxt = 'Desactivado'; if ($r.Rdp) { $rdpTxt = 'ACTIVADO' }
    Write-Dato 'Escritorio remoto' $rdpTxt

    Write-Titulo 'RESULTADO'
    if ($r.NAlto) { Write-Host "  [!] $($r.NAlto) problema(s) GRAVE(S) y $($r.NMed) a revisar." -ForegroundColor Red }
    elseif ($r.NMed) { Write-Host "  [~] Nada grave, pero hay $($r.NMed) punto(s) a revisar." -ForegroundColor Yellow }
    else { Write-Host '  [OK] Todo se ve bien. No se detectaron señales de intrusión.' -ForegroundColor Green }
    foreach ($h in $r.Hallazgos) {
        Write-Host ''
        Write-Host "  [$($h.Nivel)] $($h.Titulo)" -ForegroundColor (Get-Color $h.Nivel)
        foreach ($l in ($h.Detalle -split "`n")) { Write-Host "      $l" -ForegroundColor Gray }
        Write-Host "      → $($h.Consejo)" -ForegroundColor White
    }
    Write-Host ''
    Write-Host "  Puntaje de seguridad: $($r.Puntaje)/100 ($($r.Calificacion))" -ForegroundColor Cyan
    Write-Host "  Reporte guardado en: $($r.Archivo)" -ForegroundColor Cyan
    Write-Host '  Creando el PDF...' -ForegroundColor DarkGray
    $pdf = New-Pdf $r.Archivo
    if ($pdf) { Write-Host "  PDF guardado en:     $pdf" -ForegroundColor Cyan }
    if (-not $SinAbrir) { if ($pdf) { Start-Process $pdf } else { Start-Process $r.Archivo } }

    if (-not $SinPreguntas) {
        foreach ($s in $r.Sosp) {
            if ($s.PID -le 4) { continue }
            $resp = Read-Host "  ¿Cerrar el programa sospechoso '$($s.Proceso)' (PID $($s.PID))? (s/n)"
            if ($resp -match '^[sSyY]') {
                Stop-Process -Id $s.PID -Force
                if (Get-Process -Id $s.PID) { Write-Host '  No se pudo cerrar (prueba como administrador).' -ForegroundColor Yellow }
                else { Write-Host '  Programa cerrado.' -ForegroundColor Green; Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) Cerrado $($s.Proceso) PID $($s.PID) $($s.Ruta)" }
            }
        }
    }
}

# ------------------------------------------------------------ reporte HTML --
function New-Reporte($R) {
    $sb = New-Object System.Text.StringBuilder
    function A($s) { [void]$sb.Append($s) }
    function Fila($k, $v) { A "<tr><th>$k</th><td>$v</td></tr>" }
    function Badge($n) { "<span class=""b $n"">$n</span>" }
    $IconoB64 = ''
    try { $IconoB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Base 'ui\icon.png'))) } catch {}

    $verClase = 'ok'; $verTit = 'Tu red se ve segura'; $verSub = 'No se detectaron señales de intrusión.'
    if ($R.NAlto) { $verClase = 'alto'; $verTit = 'Se encontraron problemas graves'; $verSub = "$($R.NAlto) grave(s) y $($R.NMed) a revisar. Mira los hallazgos abajo." }
    elseif ($R.NMed) { $verClase = 'medio'; $verTit = 'Hay puntos a revisar'; $verSub = "Nada grave, pero hay $($R.NMed) punto(s) que conviene mirar." }
    $pts = [int]$R.Puntaje
    $colP = 'var(--ok)'; if ($pts -lt 50) { $colP = 'var(--alto)' } elseif ($pts -lt 75) { $colP = 'var(--medio)' }

    $nDisp = @($R.Disp).Count
    $nExt  = @($R.Conns | Where-Object { $_.Externa -and $_.Estado -eq 'Established' }).Count
    $nEsc  = @($R.Conns | Where-Object { $_.Expuesta }).Count
    $nHall = @($R.Hallazgos).Count
    $fechaTit = ''; $fechaLarga = ''
    if ($R.Inicio) { $fechaTit = $R.Inicio.ToString('dd-MM-yyyy HH:mm'); $fechaLarga = $R.Inicio.ToString('dddd dd MMMM yyyy, HH:mm') }

    A @"
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte RedGuard - $(HtmlEnc $fechaTit)</title>
<style>
:root{--bg:#f4f6f8;--card:#fff;--tx:#151a21;--mut:#5d6672;--bd:#e2e6ea;--ac:#0f9f86;--alto:#d93b40;--medio:#d48806;--bajo:#a39017;--ok:#23854f;--info:#2563eb}
@media screen and (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161b22;--tx:#e6eaf0;--mut:#8b95a3;--bd:#262d37;--ac:#2fd4b4;--alto:#e5484d;--medio:#f0a030;--bajo:#c9b53a;--ok:#30a46c;--info:#3b82f6}}
*{box-sizing:border-box}body{-webkit-print-color-adjust:exact;print-color-adjust:exact;margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1120px;margin:0 auto;padding:28px 16px 60px}
header{display:flex;align-items:center;gap:14px;margin-bottom:22px}header svg{width:44px;height:44px;flex:none}
h1{font-size:26px;margin:0}h1 span{color:#e8632b}.sub{color:var(--mut);font-size:14px}
h2{font-size:13px;margin:30px 0 10px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px 18px;overflow-x:auto}
.ver{display:flex;gap:18px;align-items:center;border-radius:14px;padding:18px 20px;background:var(--card);border:1px solid var(--bd)}
.score{width:74px;height:74px;border-radius:50%;display:grid;place-items:center;flex:none;background:conic-gradient($colP calc($pts*1%),var(--bd) 0)}
.score div{width:58px;height:58px;border-radius:50%;background:var(--card);display:grid;place-items:center;font-weight:700;font-size:20px}
.ver b{font-size:19px;display:block}.ver span{color:var(--mut)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px 16px}
.stat .n{font-size:26px;font-weight:700}.stat .l{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
tr:last-child td,tr:last-child th{border-bottom:0}
.kv th{width:150px;color:var(--mut);font-weight:500}thead th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td.m{font-family:Consolas,monospace;font-size:12px;white-space:nowrap}small{color:var(--mut)}
.b{display:inline-block;padding:1px 9px;border-radius:99px;font-size:10.5px;font-weight:700;color:#fff;letter-spacing:.03em}
.ALTO{background:var(--alto)}.MEDIO{background:var(--medio)}.BAJO{background:var(--bajo)}.OK{background:var(--ok)}.INFO{background:var(--info)}
.h{border:1px solid var(--bd);border-left:5px solid var(--mut);border-radius:12px;padding:12px 16px;margin:10px 0;background:var(--card)}
.h.ALTO{border-left-color:var(--alto)}.h.MEDIO{border-left-color:var(--medio)}.h.BAJO{border-left-color:var(--bajo)}.h.INFO{border-left-color:var(--info)}
.h pre{white-space:pre-wrap;margin:8px 0;color:var(--mut);font:12.5px/1.5 Consolas,monospace}
.nota{border-left:5px solid var(--ac);background:var(--card);border-radius:12px;padding:14px 18px;border-top:1px solid var(--bd);border-right:1px solid var(--bd);border-bottom:1px solid var(--bd)}
.rec{display:grid;grid-template-columns:22px 1fr;gap:4px 10px;padding:9px 0;border-bottom:1px solid var(--bd)}.rec:last-child{border-bottom:0}
.rec i{width:18px;height:18px;border-radius:50%;display:grid;place-items:center;color:#fff;font-style:normal;font-size:11px;font-weight:700;margin-top:2px}
.rec i.ok{background:var(--ok)}.rec i.mejorar{background:var(--medio)}.rec i.info{background:var(--info)}
.bp{display:grid;grid-template-columns:1fr 1fr;gap:10px 22px}.bp b{display:block}
.chip{display:inline-block;border:1px solid var(--bd);border-radius:6px;padding:0 6px;margin:1px 2px 1px 0;font-size:11.5px;white-space:nowrap}
footer{color:var(--mut);font-size:12px;margin-top:34px}
@media print{body{background:#fff}.card,.stat,.ver,.h,.rec,tr{break-inside:avoid}h2{break-after:avoid}}
</style></head><body><main>
<header><img src="data:image/png;base64,$IconoB64" alt="" style="width:46px;height:46px">
<div><h1>Red<span>Guard</span></h1><div class="sub">Reporte de seguridad de red &middot; $(HtmlEnc $R.Equipo) &middot; $(HtmlEnc $fechaLarga)</div></div></header>
<div class="ver $verClase"><div class="score"><div>$pts</div></div><div><b>$verTit</b><span>Puntaje de seguridad: $pts/100 ($(HtmlEnc $R.Calificacion)). $verSub</span></div></div>
<div class="stats">
<div class="stat"><div class="n">$nHall</div><div class="l">Hallazgos</div></div>
<div class="stat"><div class="n">$nDisp</div><div class="l">Dispositivos en tu red</div></div>
<div class="stat"><div class="n">$nExt</div><div class="l">Conexiones a Internet</div></div>
<div class="stat"><div class="n">$nEsc</div><div class="l">Puertos abiertos en este equipo</div></div>
</div>
"@

    A '<h2>Hallazgos</h2>'
    if ($nHall) {
        foreach ($h in $R.Hallazgos) { A "<div class=""h $($h.Nivel)"">$(Badge $h.Nivel) <b>$(HtmlEnc $h.Titulo)</b><pre>$(HtmlEnc $h.Detalle)</pre><div>&rarr; $(HtmlEnc $h.Consejo)</div></div>" }
    } else { A '<div class="card">No hay nada que revisar.</div>' }

    A "<h2>Nota de ciberseguridad</h2><div class=""nota"">$(HtmlEnc $NotaCiber)</div>"
    A '<h2>Recomendaciones para tu caso</h2><div class="card">'
    foreach ($c in @($R.Consejos)) {
        $ico = '&#10003;'; if ($c.Estado -eq 'mejorar') { $ico = '!' } elseif ($c.Estado -eq 'info') { $ico = 'i' }
        A "<div class=""rec""><i class=""$($c.Estado)"">$ico</i><div><b>$(HtmlEnc $c.Titulo)</b><br><span style=""color:var(--mut)"">$(HtmlEnc $c.Texto)</span></div></div>"
    }
    A '</div><h2>Buenas prácticas</h2><div class="card bp">'
    foreach ($b in $BuenasPracticas) { A "<div><b>$(HtmlEnc $b.T)</b><small>$(HtmlEnc $b.D)</small></div>" }
    A '</div>'

    A '<h2>Tu red y dónde estás conectado</h2><div class="grid"><div class="card"><table class="kv">'
    if ($R.Wifi) {
        Fila 'Wi-Fi' "<b>$(HtmlEnc $R.Wifi.SSID)</b>"
        Fila 'Seguridad' "$(HtmlEnc "$($R.Wifi.Seguridad) · $($R.Wifi.Cifrado)") $(Badge $R.SegNivel)"
        Fila 'Señal' (HtmlEnc "$($R.Wifi.Senal) · $($R.Wifi.Banda) · canal $($R.Wifi.Canal)")
        Fila 'Router (BSSID)' (HtmlEnc $R.Wifi.BSSID)
    } else { Fila 'Tipo' 'Cable / otra conexión' }
    Fila 'Adaptador' (HtmlEnc $R.Adaptador)
    Fila 'Perfil de red' (HtmlEnc $R.Perfil)
    Fila 'IP local' (HtmlEnc $R.IpLocal)
    Fila 'Puerta de enlace' (HtmlEnc $R.Gw)
    Fila 'DNS' (HtmlEnc $R.Dns)
    A '</table></div><div class="card"><table class="kv">'
    if ($R.Pub) {
        Fila 'IP pública' "<b>$(HtmlEnc $R.Pub.IP)</b>"
        Fila 'Ubicación aprox.' (HtmlEnc "$($R.Pub.Ciudad), $($R.Pub.Region), $($R.Pub.Pais)")
        Fila 'Proveedor' (HtmlEnc $R.Pub.Proveedor)
    } else { Fila 'IP pública' 'No disponible' }
    $v = 'No'; if ($R.Vpn) { $v = HtmlEnc $R.Vpn }
    Fila 'VPN' $v
    Fila 'Defender' "$(HtmlEnc $R.AvTxt) $(Badge $R.AvNivel)"
    Fila 'Firewall' "$(HtmlEnc $R.FwTxt) $(Badge $R.FwNivel)"
    $rdp = 'Desactivado'; if ($R.Rdp) { $rdp = 'Activado' }
    Fila 'Escritorio remoto' $rdp
    if ($null -ne $R.ParcheDias) { Fila 'Windows Update' "Última actualización hace $($R.ParcheDias) día(s)" }
    A '</table></div></div>'

    A "<h2>Dispositivos en tu red ($nDisp)</h2><div class=""card""><table><thead><tr><th>Dispositivo</th><th>Fabricante</th><th>IP / MAC</th><th>Servicios que ofrece</th></tr></thead><tbody>"
    foreach ($d in $R.Disp) {
        $nom = @($d.Apodo, $d.Nombre, $d.NombreUpnp) | Where-Object { $_ } | Select-Object -First 1
        $tit = "<b>$(HtmlEnc $d.Tipo)</b>"; if ($nom) { $tit = "<b>$(HtmlEnc $nom)</b><br><small>$(HtmlEnc $d.Tipo)</small>" }
        if ($d.Nuevo) { $tit += ' <span class="b MEDIO">NUEVO</span>' }
        $fab = HtmlEnc $d.Fabricante; if (-not $d.Fabricante) { if ($d.MacPrivada) { $fab = '<small>MAC privada</small>' } else { $fab = '<small>Desconocido</small>' } }
        if ($d.Modelo) { $fab += "<br><small>$(HtmlEnc $d.Modelo)</small>" }
        $chips = (@($d.Puertos) | ForEach-Object { "<span class=""chip"">$($_.P) $(HtmlEnc $_.Txt)</span>" }) -join ''
        if (-not $chips) { $chips = '<small>Ninguno de los revisados</small>' }
        A "<tr><td>$tit</td><td>$fab</td><td class=""m"">$(HtmlEnc $d.IP)<br>$(HtmlEnc $d.MAC)</td><td>$chips</td></tr>"
    }
    A '</tbody></table></div>'

    $lista = $R.Conns | Where-Object { $_.Externa -or $_.Nivel -ne 'OK' } | Sort-Object @{ e = 'Puntos'; Descending = $true }, Proceso
    A "<h2>Conexiones hacia fuera ($(@($lista).Count))</h2><div class=""card""><table><thead><tr><th>Nivel</th><th>Programa</th><th>Se conecta a</th><th>Para qué</th><th>Estado</th></tr></thead><tbody>"
    foreach ($c in $lista) {
        $prog = "<b>$(HtmlEnc $c.Proceso)</b>"; if ($c.Programa) { $prog += "<br><small>$(HtmlEnc $c.Programa)</small>" }
        $dest = HtmlEnc $c.Destino; if (-not $c.Destino) { $dest = '<small>Sin identificar</small>' }
        $dest += "<br><small class=""m"">$(HtmlEnc $c.Remota)</small>"; if ($c.Donde) { $dest += "<br><small>$(HtmlEnc $c.Donde)</small>" }
        $para = HtmlEnc $c.Servicio; if ($c.Motivos) { $para += "<br><small style=""color:var(--alto)"">$(HtmlEnc $c.Motivos)</small>" }
        A "<tr><td>$(Badge $c.Nivel)</td><td>$prog</td><td>$dest</td><td>$para</td><td>$(HtmlEnc $c.EstadoTxt)</td></tr>"
    }
    A '</tbody></table></div>'

    $esc = $R.Conns | Where-Object { $_.Expuesta } | Sort-Object @{ e = 'Puntos'; Descending = $true }, { [int]($_.Local -replace '^.*:', '') }
    A "<h2>Puertos abiertos en este equipo ($nEsc)</h2><div class=""card""><table><thead><tr><th>Puerto</th><th>Qué es</th><th>Programa</th><th>Alcance</th><th>¿Normal?</th></tr></thead><tbody>"
    foreach ($c in $esc) {
        $pt = ($c.Local -replace '^.*:', ''); $ipv = 'IPv4'; if ($c.Local -match '^\[?[0-9a-f:]*:\d+$' -and $c.Local -match '::') { $ipv = 'IPv6' }
        $norm = HtmlEnc $c.Normal; $cls = 'OK'; if ($c.Normal -eq 'Revisar') { $cls = 'MEDIO' } elseif ($c.Normal -eq 'Depende') { $cls = 'INFO' }
        if ($c.Nivel -ne 'OK') { $cls = $c.Nivel; $norm = 'Sospechoso' }
        $prog = "<b>$(HtmlEnc $c.Proceso)</b>"; if ($c.Servicios) { $prog += "<br><small>$(HtmlEnc $c.Servicios)</small>" } elseif ($c.Programa) { $prog += "<br><small>$(HtmlEnc $c.Programa)</small>" }
        A "<tr><td class=""m"">$pt<br><small>$ipv</small></td><td><b>$(HtmlEnc $c.Servicio)</b><br><small>$(HtmlEnc $c.Explicacion)</small></td><td>$prog</td><td>$(HtmlEnc $c.Alcance)</td><td><span class=""b $cls"">$norm</span></td></tr>"
    }
    A '</tbody></table></div>'

    A "<footer>RedGuard v$Version &middot; complementa a Microsoft Defender, no lo reemplaza. La ubicación viene de tu IP pública y es aproximada.<br>$(HtmlEnc $NotaPrivacidad)</footer></main></body></html>"
    return $sb.ToString()
}

# --------------------------------------------------------------- monitor ----
function Start-Monitoreo {
    Clear-Host
    Write-Host ''
    Write-Host "  RedGuard v$Version - VIGILANCIA EN VIVO" -ForegroundColor Cyan
    Write-Host "  Reviso tus conexiones cada $Intervalo s y te aviso si aparece algo sospechoso." -ForegroundColor Gray
    Write-Host "  Alertas guardadas en: $Log" -ForegroundColor DarkGray
    Write-Host '  Cierra esta ventana o pulsa Ctrl+C para detener.' -ForegroundColor DarkGray
    Write-Host ''
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $ni = New-Object System.Windows.Forms.NotifyIcon
    $ni.Icon = [System.Drawing.SystemIcons]::Shield
    $ni.Text = 'RedGuard vigilando tu red'
    $ni.Visible = $true
    $vistos = @{}
    $ssidAnt = $null
    try {
        while ($true) {
            $w = Get-InfoWifi
            $ssid = ''; if ($w) { $ssid = $w.SSID }
            if ($null -ne $ssidAnt -and $ssid -ne $ssidAnt) {
                $m = "Cambio de red: '$ssidAnt' → '$ssid'"
                if ($w -and $w.Seguridad -match 'Abierta|Open') { $m += ' (RED ABIERTA, sin contraseña)' }
                Write-Host "`n  $(Get-Date -Format 'HH:mm:ss')  $m" -ForegroundColor Yellow
                Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) $m"
                $ni.ShowBalloonTip(8000, 'RedGuard: cambiaste de red', $m, [System.Windows.Forms.ToolTipIcon]::Info)
            }
            $ssidAnt = $ssid

            $c = Get-AnalisisConexiones
            foreach ($x in ($c | Where-Object { $_.Nivel -in @('ALTO','MEDIO') })) {
                $k = "$($x.PID)|$($x.Local)|$($x.Remota)"
                if ($vistos.ContainsKey($k)) { continue }
                $vistos[$k] = $true
                $msg = "[{0}] {1} (PID {2})  {3} → {4}  |  {5}" -f $x.Nivel, $x.Proceso, $x.PID, $x.Local, $x.Remota, $x.Motivos
                Write-Host "`n  $(Get-Date -Format 'HH:mm:ss')  $msg" -ForegroundColor (Get-Color $x.Nivel)
                if ($x.Ruta) { Write-Host "            Archivo: $($x.Ruta)" -ForegroundColor Gray }
                Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) $msg  $($x.Ruta)"
                try { [Console]::Beep(1000, 300) } catch {}
                $ni.ShowBalloonTip(10000, "RedGuard: conexión sospechosa ($($x.Nivel))", "$($x.Proceso) → $($x.Remota)", [System.Windows.Forms.ToolTipIcon]::Warning)
            }
            $n = @($c | Where-Object { $_.Externa -and $_.Estado -eq 'Established' }).Count
            $redTxt = 'cable'; if ($ssid) { $redTxt = $ssid }
            Write-Host -NoNewline ("`r  {0}  Red: {1}  |  conexiones activas: {2}  |  alertas: {3}        " -f (Get-Date -Format 'HH:mm:ss'), $redTxt, $n, $vistos.Count) -ForegroundColor DarkGray
            Start-Sleep -Seconds $Intervalo
        }
    } finally {
        $ni.Visible = $false; $ni.Dispose()
    }
}

# ---------------------------------------------------- accesos directos -----
function Install-Accesos {
    $esc = [Environment]::GetFolderPath('Desktop')
    if (-not $esc -or -not $Base) { return }
    $web = Join-Path $Base 'RedGuard-Web.ps1'
    if (-not (Test-Path $web)) { return }
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut((Join-Path $esc 'RedGuard.lnk'))
    $s.TargetPath = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$web`""
    $s.WorkingDirectory = $Base
    $ico = Join-Path $Base 'RedGuard.ico'
    if (Test-Path $ico) { $s.IconLocation = "$ico,0" } else { $s.IconLocation = "$env:windir\System32\shell32.dll,47" }
    $s.Description = 'RedGuard - guardián de tu red'
    $s.Save()
}

# ------------------------------------------------------------------ PDF -----
function Get-RutaEdge {
    foreach ($e in @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe")) {
        if ($e -and (Test-Path $e)) { return $e }
    }
    return $null
}

function New-Pdf($html) {
    if (-not $html -or -not (Test-Path $html)) { return $null }
    $edge = Get-RutaEdge
    if (-not $edge) { return $null }
    $pdf = [IO.Path]::ChangeExtension($html, '.pdf')
    Remove-Item $pdf -Force
    $perfil = Join-Path $env:TEMP 'RedGuard-Edge'
    $url = ([Uri]$html).AbsoluteUri
    $argsEdge = "--headless --disable-gpu --no-first-run --no-default-browser-check --disable-extensions --user-data-dir=`"$perfil`" --no-pdf-header-footer --print-to-pdf-no-header --print-to-pdf=`"$pdf`" `"$url`""
    $p = Start-Process -FilePath $edge -ArgumentList $argsEdge -WindowStyle Hidden -PassThru
    if ($p) { [void]$p.WaitForExit(60000) }
    for ($i = 0; $i -lt 40 -and -not (Test-Path $pdf); $i++) { Start-Sleep -Milliseconds 250 }
    if (Test-Path $pdf) { return $pdf }
    return $null
}

# -------------------------------------------------- modo JSON (app HTML5) ---
function ConvertTo-Dto($r, $pdf) {
    $w = $r.Wifi; $p = $r.Pub
    $red = [ordered]@{
        Conectado = [bool]$r.Cfg; Wifi = [bool]$w; Ssid = $w.SSID; Seguridad = $w.Seguridad; Cifrado = $w.Cifrado
        Senal = $w.Senal; Banda = $w.Banda; Canal = $w.Canal; Radio = $w.Radio; Bssid = $w.BSSID; SegNivel = $r.SegNivel
        Adaptador = $r.Adaptador; Perfil = $r.Perfil; IpLocal = $r.IpLocal; Gw = $r.Gw; Dns = $r.Dns; Vpn = $r.Vpn
    }
    $pubDto = $null
    if ($p) { $pubDto = [ordered]@{ IP = $p.IP; Ciudad = $p.Ciudad; Region = $p.Region; Pais = $p.Pais; Proveedor = $p.Proveedor; Coord = $p.Coord } }
    $prot = [ordered]@{ AvTxt = $r.AvTxt; AvNivel = $r.AvNivel; FirmasDias = $r.FirmasDias; FwTxt = $r.FwTxt; FwNivel = $r.FwNivel; Rdp = [bool]$r.Rdp; Proxy = $r.Proxy; ParcheDias = $r.ParcheDias }
    $conns = @($r.Conns | Where-Object { $_ -and ($_.Externa -or $_.Nivel -ne 'OK') -and -not $_.Escucha } | Sort-Object @{ e = 'Puntos'; Descending = $true }, Proceso |
        Select-Object Nivel, Puntos, Proceso, Programa, Empresa, Servicios, PID, Estado, EstadoTxt, Local, Remota, IpRemota, Destino, Host, Org, Cc, Donde, Servicio, Motivos, Ruta)
    $puertos = @($r.Conns | Where-Object { $_ -and $_.Expuesta } | Sort-Object @{ e = 'Puntos'; Descending = $true }, { [int]($_.Local -replace '^.*:', '') } |
        Select-Object Nivel, Proceso, Programa, Servicios, PID, Local, Servicio, Explicacion, Normal, Alcance, Motivos, Ruta)
    $disp = New-Object System.Collections.ArrayList
    foreach ($d in @($r.Disp | Where-Object { $_ })) {
        $pts = New-Object System.Collections.ArrayList
        foreach ($x in @($d.Puertos | Where-Object { $_ })) { [void]$pts.Add([ordered]@{ P = [int]$x.P; Txt = [string]$x.Txt }) }
        [void]$disp.Add([ordered]@{
            IP = $d.IP; MAC = $d.MAC; Fabricante = $d.Fabricante; MacPrivada = [bool]$d.MacPrivada; Nombre = $d.Nombre; NombreUpnp = $d.NombreUpnp
            Modelo = $d.Modelo; Tipo = $d.Tipo; Clase = $d.Clase; Nota = $d.Nota; EsEste = [bool]$d.EsEste; EsRouter = [bool]$d.EsRouter
            Nuevo = [bool]$d.Nuevo; Primera = $d.Primera; Apodo = $d.Apodo; Puertos = $pts; Servicios = [string]$d.Servicios; Via = [string]$d.Via
        })
    }
    $fecha = Get-Date; if ($r.Inicio) { $fecha = $r.Inicio }
    $pdfName = ''; if ($pdf) { $pdfName = Split-Path $pdf -Leaf }
    $repName = ''; if ($r.Archivo) { $repName = Split-Path $r.Archivo -Leaf }
    return [ordered]@{
        Version = $Version; Fecha = $fecha.ToString('s'); FechaTxt = $fecha.ToString('dd-MM-yyyy HH:mm'); Equipo = $env:COMPUTERNAME
        Red = $red; Pub = $pubDto; Proteccion = $prot
        Hallazgos = @($r.Hallazgos | Where-Object { $_ } | Select-Object Nivel, Titulo, Detalle, Consejo)
        NAlto = [int]$r.NAlto; NMed = [int]$r.NMed; Puntaje = [int]$r.Puntaje; Calificacion = $r.Calificacion
        Consejos = @($r.Consejos | Where-Object { $_ } | Select-Object Estado, Titulo, Texto)
        Nota = $NotaCiber; Practicas = @($BuenasPracticas | ForEach-Object { [ordered]@{ T = $_.T; D = $_.D } }); Privacidad = $NotaPrivacidad
        Dispositivos = $disp; Conexiones = $conns; Puertos = $puertos
        NExt = @($r.Conns | Where-Object { $_ -and $_.Externa -and $_.Estado -eq 'Established' }).Count
        Reporte = $repName; Pdf = $pdfName
    }
}

function Write-Diagnostico($dir, $r, $extra) {
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("Fecha: $(Get-Date -Format s)   RedGuard $Version")
    $l.Add("PowerShell $($PSVersionTable.PSVersion)  Modo: $($ExecutionContext.SessionState.LanguageMode)  Admin: $EsAdmin  Arq: $env:PROCESSOR_ARCHITECTURE")
    $l.Add("Resultado nulo: $($null -eq $r)")
    if ($r) { $l.Add("Cfg: $([bool]$r.Cfg)  Wifi: $([bool]$r.Wifi)  Disp: $(@($r.Disp).Count)  Conns: $(@($r.Conns).Count)  Pub: $([bool]$r.Pub)  Defender: $([bool]$r.Mp)") }
    if ($extra) { $l.Add($extra) }
    if ($script:DiagRed) { $l.Add("Red: $($script:DiagRed)") }
    $l.Add("Errores registrados: $($Error.Count)")
    foreach ($e in ($Error | Where-Object { "$_" -notmatch 'Receive|MSFT_Net|NetConnectionProfile|no existe' } | Select-Object -First 40)) {
        $pos = ''; if ($e.InvocationInfo) { $pos = ($e.InvocationInfo.PositionMessage -split "`n")[0] }
        $l.Add("- $e   $pos")
    }
    try { [IO.File]::WriteAllText((Join-Path $dir 'diagnostico.txt'), ($l -join "`r`n")) } catch {}
}

function Invoke-ExportarJson($dir) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $script:ArchivoProgreso = Join-Path $dir 'progreso.json'
    $Error.Clear()
    $r = Get-Revision
    $pdf = $null
    if ($r -and $r.Archivo) { Set-Progreso 'Creando el PDF del reporte...' 97; $pdf = New-Pdf $r.Archivo }
    $json = ConvertTo-Json (ConvertTo-Dto $r $pdf) -Depth 6 -Compress
    $tmp = Join-Path $dir 'resultado.tmp'
    [IO.File]::WriteAllText($tmp, $json)
    Move-Item $tmp (Join-Path $dir 'resultado.json') -Force
    Write-Diagnostico $dir $r "PDF: $pdf"
    Set-Progreso 'Listo' 100
}

# ------------------------------------- vulnerabilidades explotadas (KEV) ----
$TiposKev = [ordered]@{
    'Unchecked Return Value to NULL Pointer Dereference' = 'Puntero nulo (caída)'
    'Missing Authentication for Critical Function' = 'Falta de autenticación en función crítica'
    'Generation of Predictable Numbers or Identifiers' = 'Identificadores predecibles'
    'Unrestricted Upload of File with Dangerous Type' = 'Subida de archivos peligrosos'
    'Improper Neutralization of Encoded URI Schemes' = 'URI codificadas sin filtrar'
    'Improper Restriction of Operations within the Bounds' = 'Desbordamiento de búfer'
    'Files or Directories Accessible to External' = 'Archivos accesibles desde fuera'
    'Cleartext Storage of Sensitive Information' = 'Datos sensibles sin cifrar'
    'Missing Initialization of a Variable' = 'Variable sin inicializar'
    'Authentication Bypass by Spoofing' = 'Evasión de autenticación'
    'Server-Side Request Forgery' = 'Falsificación de peticiones (SSRF)'
    'Uncontrolled Search Path Element' = 'Ruta de búsqueda no controlada (DLL)'
    'External Control of File Name or Path' = 'Control externo de rutas'
    'Improper Privilege Management' = 'Gestión de privilegios incorrecta'
    'Integer Overflow or Wraparound' = 'Desbordamiento de entero'
    'Stale Internal Request-State' = 'Estado de petición obsoleto'
    'Heap-Based Buffer Overflow' = 'Desbordamiento de memoria'
    'Out-of-Bounds Write' = 'Escritura fuera de límites'
    'Out of Bounds Write' = 'Escritura fuera de límites'
    'Out-of-Bounds Read' = 'Lectura fuera de límites'
    'Improper Access Control' = 'Control de acceso incorrecto'
    'Improper Authentication' = 'Autenticación incorrecta'
    'Improper Input Validation' = 'Validación de entrada incorrecta'
    'Unchecked Return Value' = 'Valor de retorno sin verificar'
    'Relative Path Traversal' = 'Recorrido de rutas'
    'Insufficient Logging' = 'Registro insuficiente'
    'Data Processing Errors' = 'Error de procesamiento (caída)'
    'OS Command Injection' = 'Inyección de comandos'
    'Command Injection' = 'Inyección de comandos'
    'Code Injection' = 'Inyección de código'
    'SQL Injection' = 'Inyección SQL'
    'Session Fixation' = 'Fijación de sesión'
    'Memory Corruption' = 'Corrupción de memoria'
    'Path Traversal' = 'Recorrido de rutas'
    'Type Confusion' = 'Confusión de tipos'
    'Use-After-Free' = 'Uso de memoria liberada'
    'Use After Free' = 'Uso de memoria liberada'
    'Double Free' = 'Doble liberación de memoria'
    'Link Following' = 'Seguimiento de enlaces'
    'Deserialization of Untrusted Data' = 'Deserialización insegura'
    'Cross-Site Scripting' = 'Cross-site scripting (XSS)'
    'Privilege Escalation' = 'Elevación de privilegios'
    'Remote Code Execution' = 'Ejecución remota de código'
    'Security Feature Bypass' = 'Evasión de una protección'
    'Incorrect Authorization' = 'Autorización incorrecta'
    'Remote File Inclusion' = 'Inclusión remota de archivos'
}
function Get-TipoKev($nombre) {
    foreach ($k in $TiposKev.Keys) { if ($nombre -like "*$k*") { return $TiposKev[$k] } }
    return (([string]$nombre) -replace '\s*Vulnerability\s*$', '')
}

function Get-SoftwareInstalado {
    $l = New-Object System.Collections.Generic.List[object]
    foreach ($k in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        foreach ($i in @(Get-ItemProperty $k)) {
            if ($i.DisplayName) { $l.Add([pscustomobject]@{ Nombre = [string]$i.DisplayName; Version = [string]$i.DisplayVersion; Editor = [string]$i.Publisher }) }
        }
    }
    try { foreach ($a in @(Get-AppxPackage)) { $l.Add([pscustomobject]@{ Nombre = ([string]$a.Name -replace '^[^.]+\.', ''); Version = [string]$a.Version; Editor = [string]$a.Publisher }) } } catch {}
    return $l.ToArray()
}

function Invoke-Vulnerabilidades($dir) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $prog = Join-Path $dir 'vuln-progreso.json'
    [IO.File]::WriteAllText($prog, '{"Estado":"Descargando el catálogo de CISA..."}')
    $f = Join-Path $dir 'kev.json'
    $fresco = (Test-Path $f) -and (((Get-Date) - (Get-Item $f).LastWriteTime).TotalHours -lt 6)
    if (-not $fresco) {
        foreach ($u in @('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                         'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')) {
            try {
                Invoke-WebRequest -Uri $u -OutFile "$f.tmp" -TimeoutSec 45 -UseBasicParsing -ErrorAction Stop
                if ((Get-Item "$f.tmp").Length -gt 100000) { Move-Item "$f.tmp" $f -Force; break }
            } catch {}
        }
    }
    if (-not (Test-Path $f)) {
        [IO.File]::WriteAllText((Join-Path $dir 'vulnerabilidades.json'), (ConvertTo-Json @{ Error = 'No se pudo descargar el catálogo de CISA. Revisa tu conexión.'; Fecha = (Get-Date).ToString('s') } -Compress))
        return
    }
    [IO.File]::WriteAllText($prog, '{"Estado":"Comparando con tus programas y dispositivos..."}')
    Add-Type -AssemblyName System.Web.Extensions
    $js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $js.MaxJsonLength = [int]::MaxValue
    $kev = $js.DeserializeObject([IO.File]::ReadAllText($f, [Text.Encoding]::UTF8))

    $sw = @(Get-SoftwareInstalado)
    $swTxt = (($sw | ForEach-Object { $_.Nombre }) -join ' | ').ToLower()
    $navs = @($sw | Where-Object { $_.Nombre -match '^(Google Chrome|Microsoft Edge|Brave|Opera|Vivaldi|Mozilla Firefox)' } |
              ForEach-Object { "$($_.Nombre) $($_.Version)".Trim() } | Select-Object -Unique)
    # fecha de la última actualización de cada navegador (archivo del ejecutable)
    $navFecha = $null
    foreach ($exe in @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
                       "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                       "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")) {
        if ($exe -and (Test-Path $exe)) {
            $fx = (Get-Item $exe).LastWriteTime
            $carp = Get-ChildItem (Split-Path $exe) -Directory | Where-Object { $_.Name -match '^\d+\.' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($carp -and $carp.LastWriteTime -gt $fx) { $fx = $carp.LastWriteTime }
            if (-not $navFecha -or $fx -lt $navFecha) { $navFecha = $fx }   # el navegador menos actualizado manda
        }
    }
    $ultimoParche = $null
    try { $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($hf) { $ultimoParche = [datetime]$hf.InstalledOn } } catch {}
    $fabRed = @()
    $rf = Join-Path $dir 'resultado.json'
    if (Test-Path $rf) {
        try { $rj = [IO.File]::ReadAllText($rf, [Text.Encoding]::UTF8) | ConvertFrom-Json; $fabRed = @($rj.Dispositivos | Where-Object { $_.Fabricante -and -not $_.EsEste } | ForEach-Object { [string]$_.Fabricante }) } catch {}
    }
    $vendRed = 'mikrotik|tp-link|d-link|zyxel|netgear|huawei|zte|hikvision|dahua|synology|qnap|asus|linksys|ubiquiti|tenda|xiaomi|samsung|lg electronics|roku|sonos|axis|draytek|sonicwall|fortinet|cisco|mitrastar|sagemcom|arris|technicolor|tuya|espressif|hisense|tcl'
    $genericas = '^(multiple|products?|server|software|edition|community|enterprise|and|for|the|core|service|services|windows|microsoft|google|apple|platform|framework|manager|management|system|systems|open|source|web|online|built-in|code|data|center|secure|gateway|connect)$'

    $desde = (Get-Date).AddDays(-90).ToString('yyyy-MM-dd')
    $d30 = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')
    $todas = @($kev['vulnerabilities'])
    $lista = New-Object System.Collections.Generic.List[object]
    foreach ($v in $todas) {
        $fa = [string]$v['dateAdded']
        if ($fa -lt $desde) { continue }
        $ven = [string]$v['vendorProject']; $pro = [string]$v['product']
        $vl = $ven.ToLower(); $pl = $pro.ToLower()
        $afecta = ''; $motivo = ''; $estado = ''
        if ($vl -eq 'microsoft' -and ($pl -match 'windows|win32k|winsock|kernel|shell|smb|ntfs|common log|internet key exchange|mshtml|scripting engine|smartscreen|mark of the web|defender')) {
            $afecta = 'si'; $motivo = 'Usas Windows'
            if ($ultimoParche -and $ultimoParche -gt [datetime]$fa) { $estado = "Probablemente corregida: instalaste actualizaciones de Windows el $($ultimoParche.ToString('dd-MM-yyyy'))"; $afecta = 'corregida' }
            else { $estado = 'Instala las actualizaciones de Windows (Configuración > Windows Update)' }
        } elseif ($pl -match 'chromium|chrome|\bv8\b|skia|angle|libwebp|libvpx|brotli|dawn|webgpu' -and $navs.Count) {
            $afecta = 'posible'; $motivo = 'Tienes ' + ($navs -join ', ')
            $estado = 'Actualiza el navegador: menú > Ayuda > Acerca de, y reinícialo'
            if ($navFecha -and $navFecha -gt ([datetime]$fa).AddDays(2)) {
                $afecta = 'corregida'
                $estado = "Probablemente corregida: tus navegadores se actualizaron después (el más antiguo, el $($navFecha.ToString('dd-MM-yyyy')))"
            }
        } elseif ($vl -eq 'microsoft' -and $pl -match 'edge' -and $swTxt -match 'microsoft edge') {
            $afecta = 'posible'; $motivo = 'Tienes Microsoft Edge'; $estado = 'Actualiza Edge desde edge://settings/help'
        } else {
            $prodLimpio = ($pl -replace '[()]', '').Trim()
            $hit = $null
            $prodGenerico = ($prodLimpio.Length -lt 6) -or (@($prodLimpio -split ' ' | Where-Object { $_ -notmatch $genericas }).Count -eq 0)
            if ($prodLimpio.Length -ge 4 -and $prodLimpio -notmatch '^multiple products$') {
                $hit = $sw | Where-Object {
                    $nl = $_.Nombre.ToLower(); $ed = ([string]$_.Editor).ToLower()
                    $deMarca = $nl.Contains($vl) -or $ed.Contains($vl)
                    ($nl -match "\b$([regex]::Escape($prodLimpio))\b" -and ($deMarca -or -not $prodGenerico))
                } | Select-Object -First 1
            }
            if (-not $hit -and $vl -notmatch '^(microsoft|google|apple|linux)$') {
                $tokens = @(($pl -split '[^a-z0-9+]+') | Where-Object { $_.Length -ge 5 -and $_ -notmatch $genericas })
                foreach ($t in $tokens) { $hit = $sw | Where-Object { $_.Nombre.ToLower() -match "\b$([regex]::Escape($t))\b" -and ($_.Nombre.ToLower().Contains($vl) -or ([string]$_.Editor).ToLower().Contains($vl)) } | Select-Object -First 1; if ($hit) { break } }
            }
            if ($hit) { $afecta = 'posible'; $motivo = "Tienes instalado $($hit.Nombre) $($hit.Version)".Trim(); $estado = 'Actualiza ese programa a la última versión' }
            elseif ($vl -match $vendRed) {
                $p1 = ($vl -split '[ ,]')[0]
                $dev = $fabRed | Where-Object { $_.ToLower() -match [regex]::Escape($p1) } | Select-Object -First 1
                if ($dev) { $afecta = 'posible'; $motivo = "Hay un equipo $dev en tu red"; $estado = "Si ese equipo es un $pro, actualiza su firmware desde su app o panel" }
            }
        }
        $lista.Add([ordered]@{
            Cve = [string]$v['cveID']; Fecha = $fa; Plazo = [string]$v['dueDate']; Proveedor = $ven; Producto = $pro
            Tipo = Get-TipoKev ([string]$v['vulnerabilityName']); Descripcion = [string]$v['shortDescription']
            Ransomware = ([string]$v['knownRansomwareCampaignUse'] -eq 'Known'); Afecta = $afecta; Motivo = $motivo; Estado = $estado
        })
    }
    $orden = @{ 'si' = 0; 'posible' = 1; 'corregida' = 2; '' = 3 }
    $ord = @($lista.ToArray() | Sort-Object @{ e = { $orden[$_.Afecta] } }, @{ e = { $_.Fecha }; Descending = $true }, @{ e = { $_.Cve }; Descending = $true })
    $res = [ordered]@{
        Fecha = (Get-Date).ToString('s'); FechaTxt = (Get-Date).ToString('dd-MM-yyyy HH:mm')
        Catalogo = [string]$kev['catalogVersion']; Publicado = [string]$kev['dateReleased']; Total = $todas.Count
        Ultimos30 = @($todas | Where-Object { [string]$_['dateAdded'] -ge $d30 }).Count; Ultimos90 = $lista.Count
        Afectan = @($ord | Where-Object { $_.Afecta -in @('si','posible') }).Count
        Corregidas = @($ord | Where-Object { $_.Afecta -eq 'corregida' }).Count
        Programas = $sw.Count; Navegadores = ($navs -join ', '); UltimoParche = $(if ($ultimoParche) { $ultimoParche.ToString('dd-MM-yyyy') } else { '' })
        Lista = $ord
    }
    $tmp = Join-Path $dir 'vulnerabilidades.tmp'
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json $res -Depth 5 -Compress))
    Move-Item $tmp (Join-Path $dir 'vulnerabilidades.json') -Force
    [IO.File]::WriteAllText($prog, '{"Estado":"Listo"}')
}

# ------------------------------------------------ monitor en tiempo real ----
function Start-MonitorJson($dir) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $archivo = Join-Path $dir 'vivo.json'
    $parar = Join-Path $dir 'detener-monitor'
    $hist = New-Object System.Collections.Generic.List[object]
    $alertas = New-Object System.Collections.Generic.List[object]
    $vistos = @{}; $conocidos = @{}
    $ssidAnt = $null; $vuelta = 0
    while ($true) {
        if (Test-Path $parar) { break }
        $t0 = Get-Date
        $vuelta++
        try {
            $w = Get-InfoWifi
            $ssid = ''; if ($w) { $ssid = [string]$w.SSID }
            if ($vuelta -gt 1 -and $ssid -ne $ssidAnt) {
                $niv = 'INFO'; $det = "Antes: '$ssidAnt'"
                if ($w -and $w.Seguridad -match 'Abierta|Open') { $niv = 'ALTO'; $det += ' · La nueva red NO tiene contraseña' }
                $txtRed = 'cable o sin conexión'; if ($ssid) { $txtRed = "'$ssid'" }
                $alertas.Insert(0, [pscustomobject]@{ Id = "red|$($t0.Ticks)"; Hora = $t0.ToString('HH:mm:ss'); Nivel = $niv; Titulo = "Cambiaste de red: $txtRed"; Detalle = $det; PID = 0; Proceso = '' })
                Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) Cambio de red: '$ssidAnt' → '$ssid'"
            }
            $ssidAnt = $ssid

            $c = @(Get-AnalisisConexiones)
            if ($vuelta % 4 -eq 1) { Update-InfoIps @($c | Where-Object { $_.Externa } | ForEach-Object { $_.IpRemota }) }
            Add-InfoConexiones $c $null -SinConsultar
            if ($vuelta % 6 -eq 2) {
                $cfgM = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
                $con = Get-Conocidos
                if ($cfgM -and $con.Count -and (Test-Path (Join-Path $Base 'datos\base-dispositivos.ok'))) {
                    $cambio = $false
                    foreach ($vv in @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $cfgM.InterfaceIndex | Where-Object {
                            ([string]$_.State) -in @('Reachable','Stale','Delay','Probe') -and $_.LinkLayerAddress -and
                            $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.' -and $_.IPAddress -notmatch '\.255$' })) {
                        $mac = ([string]$vv.LinkLayerAddress).ToUpper()
                        if ($con.ContainsKey($mac)) { continue }
                        $fab = 'MAC privada (probablemente un celular)'
                        if (-not (Test-MacPrivada $mac)) { $fab = Get-Fabricante $mac; if (-not $fab) { $fab = 'fabricante desconocido' } }
                        $con[$mac] = [pscustomobject]@{ Primera = $t0.ToString('s'); Ultima = $t0.ToString('s'); Apodo = ''; Ip = [string]$vv.IPAddress; Fabricante = $fab; Tipo = '' }
                        $cambio = $true
                        $alertas.Insert(0, [pscustomobject]@{ Id = "disp|$mac"; Hora = $t0.ToString('HH:mm:ss'); Nivel = 'MEDIO'; Titulo = 'Dispositivo nuevo en tu red'
                            Detalle = "$($vv.IPAddress) · $mac · $fab"; PID = 0; Proceso = '' })
                        Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) Dispositivo nuevo: $($vv.IPAddress) $mac $fab"
                    }
                    if ($cambio) { Save-Conocidos $con }
                }
            }
            $ext = @($c | Where-Object { $_.Externa -and $_.Estado -eq 'Established' })
            $esc = @($c | Where-Object { $_.Expuesta })
            foreach ($x in ($c | Where-Object { $_.Nivel -in @('ALTO','MEDIO') })) {
                $k = "$($x.PID)|$($x.Local)|$($x.Remota)"
                if ($vistos.ContainsKey($k)) { continue }
                $vistos[$k] = $true
                $alertas.Insert(0, [pscustomobject]@{ Id = "$k|$($t0.Ticks)"; Hora = $t0.ToString('HH:mm:ss'); Nivel = $x.Nivel
                    Titulo = "Conexión sospechosa: $($x.Proceso)"; Detalle = "$($x.Local) → $($x.Remota) $($x.Destino) · $($x.Motivos)"; PID = $x.PID; Proceso = $x.Proceso })
                Add-Content -Encoding UTF8 $Log "$(Get-Date -Format s) [$($x.Nivel)] $($x.Proceso) PID $($x.PID) $($x.Local) -> $($x.Remota) | $($x.Motivos) | $($x.Ruta)"
            }
            while ($alertas.Count -gt 100) { $alertas.RemoveAt($alertas.Count - 1) }

            $filas = foreach ($x in ($c | Where-Object { $_.Externa -or $_.Nivel -ne 'OK' } | Sort-Object @{ e = 'Puntos'; Descending = $true }, Proceso | Select-Object -First 200)) {
                $k = "$($x.Proceso)|$($x.Remota)"
                $nueva = $false
                if (-not $conocidos.ContainsKey($k)) { $conocidos[$k] = $t0; $nueva = ($vuelta -gt 1) }
                elseif ((($t0 - $conocidos[$k]).TotalSeconds -lt 12) -and $vuelta -gt 2) { $nueva = $true }
                [pscustomobject]@{ Nivel = $x.Nivel; Proceso = $x.Proceso; Programa = $x.Programa; PID = $x.PID; Estado = $x.Estado; EstadoTxt = $x.EstadoTxt
                                   Local = $x.Local; Remota = $x.Remota; Destino = $x.Destino; Donde = $x.Donde; Host = $x.Host; Servicio = $x.Servicio
                                   Motivos = $x.Motivos; Ruta = $x.Ruta; Nueva = $nueva }
            }
            $hist.Add([pscustomobject]@{ T = $t0.ToString('HH:mm:ss'); N = $ext.Count; E = $esc.Count })
            while ($hist.Count -gt 90) { $hist.RemoveAt(0) }

            $obj = [ordered]@{
                Hora = $t0.ToString('HH:mm:ss'); Marca = [int64](($t0.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds)
                Ssid = $ssid; Seguridad = $w.Seguridad; Senal = $w.Senal
                NExt = $ext.Count; NEsc = $esc.Count; NProg = @($ext | Select-Object -ExpandProperty PID -Unique).Count
                NSosp = @($c | Where-Object { $_.Nivel -in @('ALTO','MEDIO') }).Count
                Conexiones = @($filas); Historia = $hist.ToArray(); Alertas = $alertas.ToArray()
            }
            $tmp = "$archivo.tmp"
            [IO.File]::WriteAllText($tmp, (ConvertTo-Json $obj -Depth 5 -Compress))
            Move-Item $tmp $archivo -Force
        } catch {
            try { Add-Content -Encoding UTF8 (Join-Path $dir 'monitor-errores.log') "$(Get-Date -Format s) $($_.Exception.Message) (línea $($_.InvocationInfo.ScriptLineNumber))" } catch {}
        }
        $espera = 5000 - [int]((Get-Date) - $t0).TotalMilliseconds
        if ($espera -gt 200) { Start-Sleep -Milliseconds $espera }
    }
}

# ------------------------------------------------------------------ main ----
if ($SoloFunciones) { return }
if ($ExportarJson) { Invoke-ExportarJson $ExportarJson; return }
if ($MonitorJson)  { Start-MonitorJson $MonitorJson; return }
if ($Vulnerabilidades) { Invoke-Vulnerabilidades $Vulnerabilidades; return }
Install-Accesos
if ($Monitor) { Start-Monitoreo } else { Invoke-Revision }

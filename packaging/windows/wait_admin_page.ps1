# Emby Proxy : waits until the admin page answers (used by install_service.bat).
# Prints its port and exits 0 when ready, exits 1 after the timeout.
param([int]$TimeoutSeconds = 60)
$ini = Join-Path $PSScriptRoot "emby_proxy.ini"
for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
    $port = 8098
    if (Test-Path $ini) {
        $text = Get-Content $ini -Raw
        if ($text -match '(?ms)^\[status\][^\[]*?^port\s*=\s*(\d+)') { $port = [int]$Matches[1] }
    }
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:$port/__proxy/login"
        if ($r.StatusCode -eq 200) { Write-Output $port; exit 0 }
    } catch {}
    Start-Sleep 1
}
exit 1

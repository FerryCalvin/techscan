# Restart server and run batch scans
$c = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($c) {
    $pid = $c.OwningProcess
    Write-Host "Killing PID $pid"
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
} else {
    Write-Host 'No listener on port 5000'
}

# Set env vars for this process
$env:TECHSCAN_UNIFIED = '1'
$env:TECHSCAN_ULTRA_FALLBACK_MICRO = '1'
$env:TECHSCAN_UNIFIED_MIN_TECH = '10'
$env:TECHSCAN_DEEP_FULL_TIMEOUT_S = '15'
$env:TECHSCAN_FAST_FULL_TIMEOUT_MS = '10000'
$env:TECHSCAN_PERSIST_BROWSER = '1'

# Start server
$p = Start-Process -FilePath python -ArgumentList 'run.py' -WorkingDirectory 'D:\magang\techscan' -NoNewWindow -PassThru
Write-Host "Started server PID $($p.Id)"
Start-Sleep -Seconds 4

# Health
Write-Host '---ADMIN/HEALTH---'
try { (Invoke-RestMethod 'http://127.0.0.1:5000/admin/health' -TimeoutSec 10) | ConvertTo-Json -Depth 4 } catch { Write-Host 'HEALTH ERROR'; (Invoke-WebRequest 'http://127.0.0.1:5000/admin/health' -UseBasicParsing -TimeoutSec 10).Content }

# Domains to test
$domains = @('unair.ac.id','fpk.unair.ac.id','ftmm.unair.ac.id')
foreach ($d in $domains) {
    Write-Host "`n=== SCAN: $d ==="
    try {
        (Invoke-RestMethod "http://127.0.0.1:5000/scan?domain=$d&force=1&debug=1" -TimeoutSec 120) | ConvertTo-Json -Depth 8
    } catch {
        Write-Host 'SCAN ERROR'; (Invoke-WebRequest "http://127.0.0.1:5000/scan?domain=$d&force=1&debug=1" -UseBasicParsing -TimeoutSec 120).Content
    }
}

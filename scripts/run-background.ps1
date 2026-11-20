# Runs SENTINEL without a window and restarts it if it stops.
# Started at logon by the "SENTINEL" scheduled task (see scripts/autostart.ps1).
# Output goes to data/logs/sentinel.log (rotated at 10 MB, 3 old files kept).

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$logDir = Join-Path $root 'data\logs'
New-Item -ItemType Directory -Force $logDir | Out-Null
$log = Join-Path $logDir 'sentinel.log'
$node = (Get-Command node -ErrorAction Stop).Source

function Rotate-Log {
  if ((Test-Path $log) -and (Get-Item $log).Length -gt 10MB) {
    for ($i = 2; $i -ge 1; $i--) {
      if (Test-Path "$log.$i") { Move-Item -Force "$log.$i" "$log.$($i + 1)" }
    }
    Move-Item -Force $log "$log.1"
  }
}

function Write-Log($msg) {
  Add-Content -Path $log -Encoding utf8 -Value "[$(Get-Date -Format 's')] [launcher] $msg"
}

$failures = 0
while ($true) {
  Rotate-Log
  if (-not (Test-Path (Join-Path $root 'web\dist\index.html'))) {
    Write-Log 'web/dist missing - building the web UI'
    & cmd.exe /c "npm run build >> `"$log`" 2>&1"
  }
  Write-Log 'starting SENTINEL'
  $started = Get-Date
  & cmd.exe /c "`"$node`" --env-file-if-exists=.env --import tsx server/index.ts >> `"$log`" 2>&1"
  $code = $LASTEXITCODE
  # A run that lasted over 5 minutes counts as healthy; reset the back-off.
  if (((Get-Date) - $started).TotalMinutes -gt 5) { $failures = 0 } else { $failures++ }
  $wait = [Math]::Min(300, 10 * [Math]::Pow(2, [Math]::Min($failures, 5)))
  Write-Log "SENTINEL exited with code $code - restarting in $wait s"
  Start-Sleep -Seconds $wait
}

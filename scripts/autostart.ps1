# Manage SENTINEL as a hidden background app that starts when you sign in to Windows.
#
#   npm run service:install     register + start (run once, in an Administrator terminal)
#   npm run service:status      is it running? last log lines
#   npm run service:stop        stop now (starts again at next sign-in)
#   npm run service:start       start now
#   npm run service:uninstall   stop and remove auto-start
#
# The task runs with highest privileges so SENTINEL can read the Windows Security
# event log without a terminal window open.

param([Parameter(Mandatory)][ValidateSet('install', 'uninstall', 'start', 'stop', 'status')][string]$Action)

$ErrorActionPreference = 'Stop'
$TaskName = 'SENTINEL'
$root = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $PSScriptRoot 'run-background.ps1'
$log = Join-Path $root 'data\logs\sentinel.log'
$port = if ($env:PORT) { $env:PORT } else { 3001 }

function Test-Admin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-Sentinel {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
  # Stop the launcher first so it cannot restart node, then whatever holds the port.
  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'run-background\.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
}

function Show-Status {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) { "Auto-start: installed (task '$TaskName', state $($task.State))" } else { 'Auto-start: not installed' }
  $listen = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  if ($listen) { "SENTINEL: running on http://127.0.0.1:$port (pid $($listen[0].OwningProcess))" } else { 'SENTINEL: not running' }
  if (Test-Path $log) { "`nLast log lines ($log):"; Get-Content $log -Tail 10 }
}

switch ($Action) {
  'install' {
    if (-not (Test-Admin)) { throw 'Run this in a terminal opened with "Run as administrator" (needed once to register the task).' }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
    # conhost --headless gives the launcher a console that is never shown.
    $taskAction = New-ScheduledTaskAction -Execute $conhost -Argument "--headless `"$ps`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$launcher`"" -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Stop-Sentinel
    Register-ScheduledTask -TaskName $TaskName -Description 'SENTINEL security monitoring (background, starts at sign-in)' -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    "Installed. SENTINEL now starts hidden every time you sign in."
    "Open http://127.0.0.1:$port"
  }
  'uninstall' {
    if (-not (Test-Admin)) { throw 'Run this in a terminal opened with "Run as administrator".' }
    Stop-Sentinel
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
    'Auto-start removed and SENTINEL stopped.'
  }
  'start' {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Start-ScheduledTask -TaskName $TaskName; 'Started.' }
    else { throw 'Auto-start is not installed. Run: npm run service:install' }
  }
  'stop' { Stop-Sentinel; 'Stopped. It will start again at your next sign-in.' }
  'status' { Show-Status }
}

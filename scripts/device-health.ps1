# Read-only device health snapshot for SENTINEL. Prints one JSON object.
# Every section is independent: a failure yields null for that section, never an exception.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Try-Get([scriptblock]$b) { try { & $b } catch { $null } }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$defender = Try-Get {
  $s = Get-MpComputerStatus
  [ordered]@{
    antivirusEnabled = [bool]$s.AntivirusEnabled
    realTimeProtection = [bool]$s.RealTimeProtectionEnabled
    tamperProtected = [bool]$s.IsTamperProtected
    signatureAgeDays = [int]$s.AntivirusSignatureAge
    signatureVersion = [string]$s.AntivirusSignatureVersion
    quickScanAgeDays = [int]$s.QuickScanAge
    fullScanAgeDays = [int]$s.FullScanAge
    lastQuickScan = if ($s.QuickScanEndTime) { $s.QuickScanEndTime.ToUniversalTime().ToString('o') } else { $null }
  }
}

$updates = Try-Get {
  $last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
  $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
  [ordered]@{
    lastInstalled = if ($last) { $last.InstalledOn.ToUniversalTime().ToString('o') } else { $null }
    lastHotfix = if ($last) { [string]$last.HotFixID } else { $null }
    rebootPending = [bool]$reboot
  }
}

$firewall = Try-Get { @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled } }) }

$encryption = Try-Get {
  if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { return [ordered]@{ available = $false } }
  if (-not $isAdmin) { return [ordered]@{ available = $true; needsAdmin = $true } }
  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
  [ordered]@{ available = $true; drive = $env:SystemDrive; protection = [string]$v.ProtectionStatus; status = [string]$v.VolumeStatus; percent = [double]$v.EncryptionPercentage }
}

$disks = Try-Get {
  @(Get-PhysicalDisk | ForEach-Object {
    $d = $_
    $rel = if ($isAdmin) { Try-Get { $d | Get-StorageReliabilityCounter } } else { $null }
    [ordered]@{
      name = [string]$d.FriendlyName
      media = [string]$d.MediaType
      sizeGb = [math]::Round($d.Size / 1GB)
      health = [string]$d.HealthStatus
      operational = (@($d.OperationalStatus) -join ', ')
      wearPct = if ($rel -and $null -ne $rel.Wear) { [int]$rel.Wear } else { $null }
      temperatureC = if ($rel -and $rel.Temperature) { [int]$rel.Temperature } else { $null }
    }
  })
}

$battery = Try-Get {
  # root\wmi BatteryStaticData fails on many laptops; powercfg's report is reliable. Temp file is removed right away.
  if (-not (Get-CimInstance Win32_Battery)) { return $null }
  $f = Join-Path $env:TEMP ("sentinel-battery-{0}.xml" -f [guid]::NewGuid())
  try {
    powercfg /batteryreport /xml /output $f | Out-Null
    [xml]$x = Get-Content -LiteralPath $f -Raw
    $b = @($x.BatteryReport.Batteries.Battery)[0]
    if ($b -and [int]$b.DesignCapacity -gt 0) { [ordered]@{ designMWh = [int]$b.DesignCapacity; fullMWh = [int]$b.FullChargeCapacity; cycles = if ($b.CycleCount) { [int]$b.CycleCount } else { $null } } } else { $null }
  } finally { Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue }
}

$exclusions = Try-Get {
  if (-not $isAdmin) { return [ordered]@{ needsAdmin = $true } }
  $p = Get-MpPreference
  [ordered]@{ paths = @($p.ExclusionPath | Where-Object { $_ }); processes = @($p.ExclusionProcess | Where-Object { $_ }); extensions = @($p.ExclusionExtension | Where-Object { $_ }) }
}

$startup = Try-Get {
  @(Get-CimInstance Win32_StartupCommand | ForEach-Object { [ordered]@{ name = [string]$_.Name; command = [string]$_.Command; location = [string]$_.Location; user = [string]$_.User } })
}

$tasks = Try-Get {
  @(Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object {
    $exec = @($_.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' } | ForEach-Object { (($_.Execute, $_.Arguments) | Where-Object { $_ }) -join ' ' })
    [ordered]@{ path = [string]$_.TaskPath; name = [string]$_.TaskName; author = [string]$_.Author; exec = ($exec -join ' ; ') }
  })
}

$uac = Try-Get {
  $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  [ordered]@{ enableLua = $k.EnableLUA; consentAdmin = $k.ConsentPromptBehaviorAdmin; secureDesktop = $k.PromptOnSecureDesktop }
}

# Installed software and services, matched against known remote-access tools in TypeScript.
$software = Try-Get {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $entries = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
  $programs = @($entries | ForEach-Object { [string]$_.DisplayName } | Sort-Object -Unique)
  # Real programs only (no hidden components, patches or updates): used to spot newly installed software.
  $apps = @($entries | Where-Object { $_.SystemComponent -ne 1 -and -not $_.ParentKeyName -and [string]$_.ReleaseType -notmatch 'Update|Hotfix' } | ForEach-Object {
    [ordered]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher; location = [string]$_.InstallLocation; icon = [string]$_.DisplayIcon; date = [string]$_.InstallDate }
  })
  $services = @(Get-CimInstance Win32_Service | ForEach-Object { [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; path = [string]$_.PathName; state = [string]$_.State } })
  [ordered]@{ programs = $programs; services = $services; apps = $apps }
}

# TCP ports that accept connections from any network (bound to 0.0.0.0 or ::).
$listeners = Try-Get {
  $procs = @{}
  Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_ }
  @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    [ordered]@{ port = [int]$_.LocalPort; process = if ($p) { [string]$p.Name } else { "" }; path = if ($p -and $p.Path) { [string]$p.Path } else { "" } }
  })
}

# Name resolution and proxies (read-only): the hosts file, DNS servers typed in by hand, proxy / PAC settings.
# Each list comes with an *Ok flag so "nothing there" is not mistaken for "could not read".
$network = Try-Get {
  $hostsOk = $true; $dnsOk = $true; $proxyOk = $true; $nrptOk = $true
  $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
  $hosts = @(try { Get-Content -LiteralPath $hostsFile -Encoding Default -ErrorAction Stop | ForEach-Object { ($_ -replace '#.*', '').Trim() } | Where-Object { $_ } } catch { $hostsOk = $false })
  $alias = @{}
  try { Get-NetAdapter -IncludeHidden | ForEach-Object { $alias[([string]$_.InterfaceGuid).ToLower()] = [string]$_.Name } } catch { }
  $dns = @(try {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces', 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces' -ErrorAction Stop | ForEach-Object {
      $p = Get-ItemProperty $_.PSPath
      $g = $_.PSChildName.ToLower()
      if ($p.NameServer) { [ordered]@{ iface = $g; name = [string]$alias[$g]; servers = @(([string]$p.NameServer) -split '[,\s]+' | Where-Object { $_ }) } }
    }
  } catch { $dnsOk = $false })
  $proxies = @(try {
    $keys = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { [pscustomobject]@{ who = $_.PSChildName; path = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" } })
    $keys += [pscustomobject]@{ who = 'machine'; path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' }
    $keys += [pscustomobject]@{ who = 'policy'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' }
    $keys | ForEach-Object {
      $p = try { Get-ItemProperty -LiteralPath $_.path -ErrorAction Stop } catch { $null }
      if ($p -and (($p.ProxyEnable -eq 1 -and $p.ProxyServer) -or $p.AutoConfigURL)) {
        [ordered]@{ who = $_.who; server = if ($p.ProxyEnable -eq 1) { [string]$p.ProxyServer } else { '' }; pac = [string]$p.AutoConfigURL }
      }
    }
  } catch { $proxyOk = $false })
  # WinHTTP (services, Windows Update): binary blob, offset 8 flags (2 = proxy), 12 length, 16 proxy text.
  $winhttp = try {
    $b = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction Stop).WinHttpSettings
    if ($b -and $b.Length -ge 16 -and ([BitConverter]::ToInt32($b, 8) -band 2)) { $n = [BitConverter]::ToInt32($b, 12); if ($n -gt 0 -and 16 + $n -le $b.Length) { [Text.Encoding]::ASCII.GetString($b, 16, $n) } else { '' } } else { '' }
  } catch { $null }
  $nrpt = @(try { Get-DnsClientNrptRule -ErrorAction Stop | ForEach-Object { [ordered]@{ ns = (@($_.Namespace) | Select-Object -First 3) -join ' '; servers = @($_.NameServers | ForEach-Object { [string]$_ }) } } } catch { $nrptOk = $false })
  [ordered]@{ hosts = $hosts; hostsOk = $hostsOk; dns = $dns; dnsOk = $dnsOk; proxies = $proxies; proxyOk = $proxyOk; winhttp = $winhttp; nrpt = $nrpt; nrptOk = $nrptOk }
}

# Trusted root certificates, inbound firewall "allow" rules and a few security settings (read-only).
# Each list has an *Ok flag so "nothing there" is not mistaken for "could not read".
$system = Try-Get {
  $certsOk = $true; $fwOk = $true; $setOk = $true
  # Which physical store each root lives in (the Cert: drive merges them): the registry key names are thumbprints.
  # Order = most suspicious first: a root added for this user only, by policy, by an "enterprise", by hand on the machine,
  # or by Windows' own automatic root update (AuthRoot).
  $physical = @(
    @{ who = 'user'; path = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' },
    @{ who = 'policy'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates' },
    @{ who = 'enterprise'; path = 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates' },
    @{ who = 'machine'; path = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' },
    @{ who = 'authroot'; path = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates' }
  )
  $storeOf = @{}
  foreach ($ps in $physical) { Get-ChildItem -LiteralPath $ps.path -ErrorAction SilentlyContinue | ForEach-Object { $t = ([string]$_.PSChildName).ToUpper(); if (-not $storeOf.ContainsKey($t)) { $storeOf[$t] = $ps.who } } }
  $seen = @{}
  $certs = @(try {
    foreach ($path in @('Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root')) {
      Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {
        $tp = ([string]$_.Thumbprint).ToUpper()
        if (-not $seen.ContainsKey($tp)) {
          $seen[$tp] = $true
          $who = if ($storeOf.ContainsKey($tp)) { $storeOf[$tp] } else { 'machine' }
          [ordered]@{ thumb = $tp; subject = [string]$_.Subject; issuer = [string]$_.Issuer; friendly = [string]$_.FriendlyName; until = $_.NotAfter.ToString('yyyy-MM-dd'); store = $who }
        }
      }
    }
  } catch { $certsOk = $false })
  # Firewall rules straight from the registry (fast; Get-NetFirewallRule with filters takes minutes).
  # Only enabled inbound Allow rules are kept; the raw text is parsed on the Node side.
  $fw = @(try {
    foreach ($src in @(@{ who = 'local'; path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' }, @{ who = 'policy'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules' })) {
      if (-not (Test-Path -LiteralPath $src.path)) { continue }
      $k = Get-Item -LiteralPath $src.path -ErrorAction Stop
      foreach ($n in $k.GetValueNames()) {
        $v = [string]$k.GetValue($n)
        if ($v -match '\|Action=Allow\|' -and $v -match '\|Active=TRUE\|' -and $v -match '\|Dir=In\|') { [ordered]@{ id = [string]$n; src = $src.who; raw = $v } }
      }
    }
  } catch { $fwOk = $false })
  # Settings: only on/off facts are sent, never a stored value (e.g. no auto-logon password).
  $settings = try {
    $reg = { param($p, $n) try { (Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction Stop).$n } catch { $null } }
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $smb1 = try { [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $null }
    $users = @(try { Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled } | ForEach-Object { [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID.Value } } } catch { })
    [ordered]@{
      rdp = ((& $reg $ts 'fDenyTSConnections') -eq 0)
      rdpNla = ((& $reg "$ts\WinStations\RDP-Tcp" 'UserAuthentication') -ne 0)
      lsaPpl = (@(1, 2) -contains (& $reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'))
      wdigest = ((& $reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1)
      autoLogonPassword = ([string](& $reg $wl 'AutoAdminLogon') -eq '1' -and $null -ne (& $reg $wl 'DefaultPassword'))
      smartScreenOff = ((& $reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen') -eq 0 -or [string](& $reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled') -eq 'Off')
      smb1 = $smb1
      users = $users
    }
  } catch { $setOk = $false; $null }
  [ordered]@{ certs = $certs; certsOk = $certsOk; firewall = $fw; firewallOk = $fwOk; settings = $settings; settingsOk = $setOk }
}

[ordered]@{
  isAdmin = $isAdmin
  defender = $defender
  updates = $updates
  firewall = $firewall
  encryption = $encryption
  disks = $disks
  battery = $battery
  exclusions = $exclusions
  startup = $startup
  tasks = $tasks
  uac = $uac
  software = $software
  listeners = $listeners
  network = $network
  system = $system
} | ConvertTo-Json -Depth 5 -Compress

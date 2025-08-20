<#  ir-quick.ps1 v2 - Windows Incident Response Quick Collector
    Run as: Administrator PowerShell (5.1+ / 7+)
    Usage:
      Set-ExecutionPolicy Bypass -Scope Process -Force
      .\ir-quick.ps1 -CaseId "INC-2025-0001" -Output "C:\IR" -Days 2 -Zip
      .\ir-quick.ps1 -CaseId "INC-2025-0001" -Isolate -IsolateInbound
      .\ir-quick.ps1 -CaseId "INC-2025-0001" -RevertIsolation
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$CaseId,
  [string]$Output = ".\IR",
  [int]$Days = 2,
  [switch]$Isolate,          # Block all outbound
  [switch]$IsolateInbound,   # Block all inbound
  [switch]$RevertIsolation,  # Remove isolation rules
  [switch]$SkipSysinternals, # (reserved) use only built-ins
  [switch]$Zip               # Zip artifacts and write SHA256
)

# --- preflight ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Run this script as Administrator."; exit 1
}
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# --- paths ---
$root = Join-Path $Output $CaseId
$meta = Join-Path $root "00_meta"
$sys  = Join-Path $root "10_system"
$evt  = Join-Path $root "20_events"
$raw  = Join-Path $evt  "raw"
$prs  = Join-Path $root "30_persistence"
$hash = Join-Path $root "40_hashes"
$reg  = Join-Path $root "50_registry"
$pf   = Join-Path $root "60_prefetch"
$def  = Join-Path $root "61_defender"
$fw   = Join-Path $root "62_firewall"
$null = New-Item -ItemType Directory -Force -Path $meta,$sys,$evt,$raw,$prs,$hash,$reg,$pf,$def,$fw

# --- transcript & meta ---
Start-Transcript -Path (Join-Path $meta "commands.log") -Force | Out-Null
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-File (Join-Path $meta "timestamp_utc.txt") -Encoding utf8
(Get-Date).ToString("yyyy-MM-dd HH:mm:ss K") | Out-File (Join-Path $meta "timestamp_local.txt") -Encoding utf8
(Get-TimeZone).Id | Out-File (Join-Path $meta "timezone.txt") -Encoding utf8
$PSVersionTable | Out-File (Join-Path $meta "powershell_version.txt") -Encoding utf8
if ($PSCommandPath) { Get-FileHash -Algorithm SHA256 $PSCommandPath | Out-File (Join-Path $meta "script_hash.txt") -Encoding utf8 }

# --- isolation controls ---
if ($RevertIsolation) {
  Get-NetFirewallRule | Where-Object DisplayName -like "IR-$CaseId-Isolation-*" | Remove-NetFirewallRule
  Write-Host "[IR] Isolation rules removed." -ForegroundColor Yellow
}

if ($Isolate) {
  New-NetFirewallRule -DisplayName "IR-$CaseId-Isolation-AllOutbound" -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null
}
if ($IsolateInbound) {
  New-NetFirewallRule -DisplayName "IR-$CaseId-Isolation-AllInbound"  -Direction Inbound  -Action Block -Profile Any -Enabled True | Out-Null
}

# --- system triage ---
Try { Get-ComputerInfo | Out-File (Join-Path $sys "computerinfo.txt") -Encoding utf8 } Catch {}
Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Version,BuildNumber,LastBootUpTime |
  Export-Csv (Join-Path $sys "os.csv") -NoTypeInformation
# processes (w/ parent + cmdline when available)
Get-CimInstance Win32_Process |
  Select-Object Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine |
  Export-Csv (Join-Path $sys "process_wmi.csv") -NoTypeInformation
# services / drivers
Get-Service | Select-Object Name,DisplayName,Status,StartType,DependentServices,ServicesDependedOn |
  Export-Csv (Join-Path $sys "services.csv") -NoTypeInformation
Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName |
  Export-Csv (Join-Path $sys "drivers.csv") -NoTypeInformation
# local admins
Try { Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource |
  Export-Csv (Join-Path $sys "local_admins.csv") -NoTypeInformation } Catch {}
# networking
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv (Join-Path $sys "net_tcp.csv") -NoTypeInformation
arp -a        | Out-File (Join-Path $sys "arp.txt") -Encoding utf8
ipconfig /all | Out-File (Join-Path $sys "ipconfig.txt") -Encoding utf8
route print   | Out-File (Join-Path $sys "route.txt") -Encoding utf8

# --- events (CSV) ---
$since = (Get-Date).AddDays(-[Math]::Max($Days,1))
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4624,4625,4672,4688,4720,4726,4732,4768,4769,4776} |
  Export-Csv (Join-Path $evt "security_core.csv") -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Id=7045,7030,6005,6006,6008} |
  Export-Csv (Join-Path $evt "system_core.csv") -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} |
  Export-Csv (Join-Path $evt "application.csv") -NoTypeInformation
if (Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue) {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since} |
    Export-Csv (Join-Path $evt "defender_operational.csv") -NoTypeInformation
}
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since} |
    Export-Csv (Join-Path $evt "sysmon_operational.csv") -NoTypeInformation
}

# --- events (RAW .evtx export) ---
$logs = @('Security','System','Application',
          'Microsoft-Windows-Windows Defender/Operational',
          'Microsoft-Windows-Sysmon/Operational')
foreach ($log in $logs) {
  Try { wevtutil epl $log (Join-Path $raw ("$($log -replace '[\\/ ]','_').evtx")) /ow:true } Catch {}
}

# --- persistence (autoruns-lite) ---
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    Try { Get-ItemProperty $k | Out-File (Join-Path $prs ("reg_" + ($k -replace "[:\\]","_") + ".txt")) -Encoding utf8 } Catch {}
  }
}
Get-ScheduledTask | Select-Object TaskName,State,TaskPath,Triggers,Actions |
  Export-Csv (Join-Path $prs "scheduled_tasks.csv") -NoTypeInformation
# startup folders
$commonStartup = "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$userStartup   = "$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem $commonStartup -Force -ErrorAction SilentlyContinue | Select FullName,LastWriteTime |
  Export-Csv (Join-Path $prs "startup_common.csv") -NoTypeInformation
Get-ChildItem $userStartup   -Force -ErrorAction SilentlyContinue | Select FullName,LastWriteTime |
  Export-Csv (Join-Path $prs "startup_user.csv") -NoTypeInformation
# WMI persistence listing
Try {
  Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Select-Object Name,Query,EventNamespace |
    Export-Csv (Join-Path $prs "wmi_event_filters.csv") -NoTypeInformation
  Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Select-Object Name,ExecutablePath,CommandLineTemplate |
    Export-Csv (Join-Path $prs "wmi_consumers.csv") -NoTypeInformation
  Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Select-Object Filter,Consumer |
    Export-Csv (Join-Path $prs "wmi_bindings.csv") -NoTypeInformation
} Catch {}

# --- registry hives & artifacts ---
reg save HKLM\SAM      "$reg\SAM.hiv" /y | Out-Null
reg save HKLM\SYSTEM   "$reg\SYSTEM.hiv" /y | Out-Null
reg save HKLM\SOFTWARE "$reg\SOFTWARE.hiv" /y | Out-Null
reg save HKLM\SECURITY "$reg\SECURITY.hiv" /y | Out-Null
Copy-Item "$env:WINDIR\appcompat\Programs\Amcache.hve" -Destination (Join-Path $reg "Amcache.hve") -ErrorAction SilentlyContinue
Copy-Item "$env:SystemRoot\Prefetch\*.pf" -Destination $pf -ErrorAction SilentlyContinue
Copy-Item "$env:ProgramData\Microsoft\Windows Defender\Support\*.*" -Destination $def -Recurse -ErrorAction SilentlyContinue
Copy-Item "$env:SystemRoot\System32\LogFiles\Firewall\*.log" -Destination $fw -ErrorAction SilentlyContinue

# --- hash sampling (recent changes in common locations) ---
$targets = @("C:\Windows\System32","C:\Program Files","C:\Program Files (x86)","C:\Users\Public")
foreach ($t in $targets) {
  if (Test-Path $t) {
    Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } |
      Select-Object FullName,Length,LastWriteTime |
      Export-Csv (Join-Path $hash ("recent_" + ($t -replace "[:\\ ]","_") + ".csv")) -NoTypeInformation
  }
}

# --- artifact inventory & zip ---
Get-ChildItem -Recurse -File $root | Get-FileHash -Algorithm SHA256 |
  Export-Csv (Join-Path $meta "artifacts_hashes.csv") -NoTypeInformation

if ($Zip) {
  $zipPath = "$root.zip"
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Compress-Archive -Path $root -DestinationPath $zipPath -Force
  Get-FileHash $zipPath -Algorithm SHA256 | Out-File "$zipPath.sha256.txt" -Encoding utf8
}

Stop-Transcript | Out-Null
Write-Host "== Done. Output: $root" -ForegroundColor Cyan

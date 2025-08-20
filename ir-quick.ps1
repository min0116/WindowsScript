<#  ir-quick.ps1 - Windows Incident Response Quick Collector
    Usage:
      Set-ExecutionPolicy Bypass -Scope Process -Force
      .\ir-quick.ps1 -CaseId "INC-2025-0001" -Output "C:\IR" -Isolate -Zip
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$CaseId,
  [string]$Output = ".\IR",
  [switch]$Isolate,
  [switch]$SkipSysinternals,
  [switch]$Zip
)

$ErrorActionPreference = "SilentlyContinue"
$root = Join-Path $Output $CaseId
$meta = Join-Path $root "00_meta"
$sys  = Join-Path $root "10_system"
$evt  = Join-Path $root "20_events"
$prs  = Join-Path $root "30_persistence"
$hash = Join-Path $root "40_hashes"

# Create folders
$null = New-Item -ItemType Directory -Force -Path $meta,$sys,$evt,$prs,$hash

# 0) Metadata / integrity
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-File (Join-Path $meta "timestamp_utc.txt")
if ($PSCommandPath) {
  Get-FileHash -Algorithm SHA256 $PSCommandPath | Out-File (Join-Path $meta "script_hash.txt")
}

# 1) System triage
Get-ComputerInfo | Out-File (Join-Path $sys "computerinfo.txt")
Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Version,BuildNumber,LastBootUpTime |
  Export-Csv (Join-Path $sys "os.csv") -NoTypeInformation
Get-Process | Sort-Object -Property StartTime -ErrorAction SilentlyContinue |
  Select-Object Name,Id,StartTime,Path,Company,ProductVersion |
  Export-Csv (Join-Path $sys "process.csv") -NoTypeInformation
Get-Service | Select-Object Name,DisplayName,Status,StartType,PathName |
  Export-Csv (Join-Path $sys "services.csv") -NoTypeInformation
Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName |
  Export-Csv (Join-Path $sys "drivers.csv") -NoTypeInformation
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv (Join-Path $sys "net_tcp.csv") -NoTypeInformation
arp -a | Out-File (Join-Path $sys "arp.txt")
ipconfig /all | Out-File (Join-Path $sys "ipconfig.txt")
route print | Out-File (Join-Path $sys "route.txt")

# 2) Events (last 48h examples)
$since = (Get-Date).AddDays(-2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=$since} |
  Export-Csv (Join-Path $evt "security_logon_4624_4625.csv") -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7030,6005,6006; StartTime=$since} |
  Export-Csv (Join-Path $evt "system_service_boot.csv") -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since} |
  Export-Csv (Join-Path $evt "defender_operational.csv") -NoTypeInformation
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since} |
    Export-Csv (Join-Path $evt "sysmon_operational.csv") -NoTypeInformation
}

# 3) Persistence (autoruns-lite without Sysinternals)
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    Get-ItemProperty $k | Out-File (Join-Path $prs ("reg_" + ($k -replace "[:\\]","_") + ".txt"))
  }
}
Get-ScheduledTask | Select-Object TaskName,State,TaskPath |
  Export-Csv (Join-Path $prs "scheduled_tasks.csv") -NoTypeInformation

# 4) Hash sample (recently modified in common locations)
$targets = @("C:\Windows\System32","C:\Program Files","C:\Program Files (x86)","C:\Users\Public")
foreach ($t in $targets) {
  if (Test-Path $t) {
    Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } |
      Select-Object FullName,Length,LastWriteTime |
      Export-Csv (Join-Path $hash ("recent_" + ($t -replace "[:\\ ]","_") + ".csv")) -NoTypeInformation
  }
}

# 5) Optional isolation
if ($Isolate) {
  New-NetFirewallRule -DisplayName "IR-$CaseId-Isolation-AllOutbound" -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null
}

# 6) Zip output
if ($Zip) {
  $zipPath = "$root.zip"
  if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
  Compress-Archive -Path $root -DestinationPath $zipPath -Force
}

Write-Host "== Done. Output: $root" -ForegroundColor Cyan
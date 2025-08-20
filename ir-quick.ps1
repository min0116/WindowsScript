<# ir-quick.ps1 (mini)
   관리자 PowerShell에서 실행
   예) Set-ExecutionPolicy Bypass -Scope Process -Force
       .\ir-quick.ps1 -CaseId INC-2025-0001 -Output C:\IR -Days 2 -Zip
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$CaseId,
  [string]$Output = ".\IR",
  [int]$Days = 2,
  [switch]$Isolate,        # 아웃바운드 전체 차단
  [switch]$RevertIsolation,# 차단 룰 제거
  [switch]$Zip             # 산출물 ZIP + SHA256
)

# --- 사전 체크 ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error "Run as Administrator."; exit 1 }
$ErrorActionPreference = "SilentlyContinue"; $ProgressPreference="SilentlyContinue"

# --- 경로 ---
$root = Join-Path $Output $CaseId
$meta = Join-Path $root "00_meta"
$sys  = Join-Path $root "10_system"
$evt  = Join-Path $root "20_events"
$raw  = Join-Path $evt  "raw"
$reg  = Join-Path $root "50_registry"
$null = New-Item -ItemType Directory -Force -Path $meta,$sys,$evt,$raw,$reg

# --- 메타/트랜스크립트 ---
Start-Transcript -Path (Join-Path $meta "commands.log") -Force | Out-Null
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-File (Join-Path $meta "timestamp_utc.txt") -Encoding utf8
(Get-TimeZone).Id | Out-File (Join-Path $meta "timezone.txt") -Encoding utf8
if ($PSCommandPath) { Get-FileHash -Algorithm SHA256 $PSCommandPath | Out-File (Join-Path $meta "script_hash.txt") -Encoding utf8 }

# --- 격리(옵션) ---
if ($RevertIsolation) { Get-NetFirewallRule | ? DisplayName -like "IR-$CaseId-Isolation-*" | Remove-NetFirewallRule }
if ($Isolate) { New-NetFirewallRule -DisplayName "IR-$CaseId-Isolation-AllOutbound" -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null }

# --- 시스템 기초 ---
Get-CimInstance Win32_OperatingSystem | Select CSName,Version,BuildNumber,LastBootUpTime |
  Export-Csv (Join-Path $sys "os.csv") -NoTypeInformation
Get-CimInstance Win32_Process | Select Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine |
  Export-Csv (Join-Path $sys "process.csv") -NoTypeInformation
Get-Service | Select Name,Status,StartType | Export-Csv (Join-Path $sys "services.csv") -NoTypeInformation
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv (Join-Path $sys "net_tcp.csv") -NoTypeInformation

# --- 이벤트 (CSV + RAW) ---
$since = (Get-Date).AddDays(-[Math]::Max($Days,1))
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4624,4625,4688} |
  Export-Csv (Join-Path $evt "security.csv") -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Id=7045,6005,6006} |
  Export-Csv (Join-Path $evt "system.csv") -NoTypeInformation
$logs = @('Security','System','Application')
if (Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue) { $logs += 'Microsoft-Windows-Windows Defender/Operational' }
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'   -ErrorAction SilentlyContinue) { $logs += 'Microsoft-Windows-Sysmon/Operational' }
foreach ($l in $logs) { try { wevtutil epl $l (Join-Path $raw ("$($l -replace '[\\/ ]','_').evtx")) /ow:true } catch {} }

# --- 레지스트리 하이브(원본 보존) ---
reg save HKLM\SAM      "$reg\SAM.hiv" /y | Out-Null
reg save HKLM\SYSTEM   "$reg\SYSTEM.hiv" /y | Out-Null
reg save HKLM\SOFTWARE "$reg\SOFTWARE.hiv" /y | Out-Null
reg save HKLM\SECURITY "$reg\SECURITY.hiv" /y | Out-Null

# --- 산출물 해시 & ZIP(옵션) ---
Get-ChildItem -Recurse -File $root | Get-FileHash -Algorithm SHA256 |
  Export-Csv (Join-Path $meta "artifacts_hashes.csv") -NoTypeInformation
if ($Zip) { $zip="$root.zip"; if (Test-Path $zip){Remove-Item $zip -Force}; Compress-Archive -Path $root -DestinationPath $zip -Force; Get-FileHash $zip -Algorithm SHA256 | Out-File "$zip.sha256.txt" -Encoding utf8 }

Stop-Transcript | Out-Null
Write-Host "== Done. Output: $root" -ForegroundColor Cyan

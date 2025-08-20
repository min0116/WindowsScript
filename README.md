# WindowsScript
8/21_homework



# Windows Incident Response Quick Collector (ir-quick.ps1)

Windows 단말에서 **현장 1차 트라이애지 + 증거 보존**을 자동화하는 PowerShell 스크립트입니다.  
관리자 권한 PowerShell(5.1 이상 또는 7+)에서 실행하세요.

---

## 📦 주요 기능

- **메타/무결성**: 실행 로그(Transcript), UTC/로컬 시각, 타임존, 스크립트 해시 기록
- **시스템 스냅샷**: OS 정보, 프로세스(PID/PPID/경로/명령행), 서비스/드라이버, 로컬 관리자
- **네트워크**: TCP 연결, ARP/IP/라우팅 덤프
- **이벤트 로그 수집**
  - CSV: Security(4624/4625/4672/4688/계정·Kerberos 관련), System(7045/6005/6006/6008), Application
  - RAW: 주요 로그 **.evtx 원본** 내보내기(Security/System/Application/Defender/Sysmon)
- **지속성(빈약 Autoruns 대체)**: Run/RunOnce, 예약작업(Trigger/Action 포함), 시작프로그램, **WMI**(Filter/Consumer/Binding)
- **레지스트리/아티팩트**: SAM/SYSTEM/SOFTWARE/SECURITY 하이브, Amcache, Prefetch, Defender Support, Windows Firewall 로그
- **격리 제어**: 아웃바운드/인바운드 전체 차단 룰 추가 및 되돌리기
- **산출물 무결성**: 산출물 전체 SHA256 목록, ZIP + SHA256 생성(옵션)

---

## 🚀 빠른 시작

```powershell
# 관리자 PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

# (선택) Raw로 다운로드 후 실행
iwr -UseBasicParsing https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/main/ir-quick.ps1 -OutFile ir-quick.ps1

# 기본 수집(48h) + ZIP
.\ir-quick.ps1 -CaseId "INC-2025-0001" -Output "C:\IR" -Days 2 -Zip

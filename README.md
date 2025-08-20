# WindowsScript
8/21_homework



## Windows IR Script (mini)

- 목적: **현장 1차 트라이애지 + 증거 원본 보존(.evtx, 레지스트리 하이브)** 자동화
- 요구: 관리자 PowerShell, 인터넷 불필요(선택적으로 ZIP 생성)

### 빠른 시작
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -UseBasicParsing https://raw.githubusercontent.com/<USER>/<REPO>/main/ir-quick.ps1 -OutFile ir-quick.ps1
.\ir-quick.ps1 -CaseId "INC-2025-0001" -Output "C:\IR" -Days 2 -Zip

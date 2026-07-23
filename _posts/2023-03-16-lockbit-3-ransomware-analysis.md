---
layout: post
title: "LockBit 3.0 분석: RaaS 침해 타임라인과 암호화 전 탐지"
description: "LockBit affiliate의 초기 접근, 자격 증명, PsExec 배포, 유출·암호화 조사"
date: 2023-03-16 10:10:00 +0900
permalink: /lockbit-3-ransomware-incident-analysis
categories: [Security, Malware]
tags: [lockbit, ransomware, raas, dfir, sigma]
---

## 분석 요약

LockBit은 운영자가 ransomware builder와 유출 인프라를 제공하고 affiliate가 피해 조직을 침해하는 RaaS다. 따라서 모든 사고가 동일한 초기 접근을 사용하지 않는다. 공통점은 암호화 전에 자격 증명 확보, 방어 기능 약화, 도메인·백업 탐색, 대량 배포가 선행된다는 점이다.

```text
VPN/RDP/phishing/exposed service
  └─ valid account
      └─ reconnaissance + credential access
          └─ PsExec/GPO/RMM deployment
              ├─ data staging + exfiltration
              └─ recovery inhibition + encryption
```

## 암호화 이전의 강한 신호

- 평소 사용하지 않던 계정의 VPN 로그인과 곧바로 이어진 SMB/RDP
- `vssadmin`, `wmic shadowcopy`, `wbadmin`, `bcdedit`의 복구 방해 명령
- PsExec 서비스 `PSEXESVC` 또는 임시 서비스의 다수 호스트 동시 생성
- EDR·백업·데이터베이스 서비스 중지
- 파일 서버·가상화 관리 서버를 향한 비정상 fan-out
- 7-Zip/WinRAR/맞춤형 도구를 이용한 대량 staging

Sigma 형태의 초기 탐지 논리는 도구명보다 명령 목적에 초점을 둔다.

```yaml
title: Shadow Copy Deletion Before Ransomware
logsource:
  category: process_creation
  product: windows
detection:
  tools:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
      - '\wbadmin.exe'
  intent:
    CommandLine|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
      - 'delete catalog'
  condition: tools and intent
```

백업 운영 작업도 같은 명령을 쓸 수 있으므로 실행 계정, maintenance window, parent process와 change ticket을 제외 조건으로 둔다.

## 조사 타임라인

암호화 시각부터 역순으로만 조사하면 최초 침해를 놓친다. 최소 30일 또는 VPN·IdP 보존기간 전체를 대상으로 다음 anchor를 연결한다.

1. 최초 비정상 인증과 source ASN
2. 첫 내부 정찰과 privilege escalation
3. LSASS/SAM/NTDS 접근
4. staging archive 생성과 외부 전송
5. GPO·PsExec·RMM을 통한 payload 배포
6. 백업 삭제, 서비스 중지, 암호화 시작

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select TimeCreated, MachineName, Message
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4672,4688}
```

Event ID 4688은 command line 감사가 사전에 활성화돼 있어야 유용하다. 중앙 EDR, Sysmon, PowerShell, VPN, IdP, firewall, file audit를 함께 사용한다.

## 유출 범위 산정

랜섬노트가 있다고 데이터가 유출됐다고 자동 확정하지 않는다. archive 생성, staging directory, egress destination, bytes transferred와 파일 접근 로그로 입증한다. 반대로 알려진 유출 도구가 없다는 이유로 배제하지 않는다. affiliate는 정상 cloud sync나 브라우저 업로드를 사용할 수 있다.

유출 목록에는 파일명뿐 아니라 소유 부서, 개인정보·기밀 분류, 접근 시각, 전송 근거의 신뢰도를 기록한다.

## 샘플 분석 안전수칙

encryptor를 실행해 보는 방식은 필요하지 않다. 정적 분석으로 PE metadata, imports, embedded configuration, mutex·extension·ransom-note 문자열을 확인하고, 동적 검증이 필요하면 가짜 파일만 있는 격리 VM에서 outbound network를 차단한다.

복호화 도구는 해당 build와 암호화 방식에 정확히 대응하는지 확인하고 원본 증거의 복사본에 먼저 시험한다. 임의 도구 실행으로 복구 가능 데이터를 덮어쓰지 않는다.

## 대응 우선순위

암호화가 진행 중이면 네트워크 격리와 ID 차단을 우선하되 전원을 무조건 끄기 전에 메모리·실행 중 프로세스·연결 정보를 보존할 가치가 있는지 판단한다. domain admin과 service account를 회전하고, 공격자가 접근한 백업의 무결성을 검증한 뒤 clean environment에서 복구한다.

## References

- [CISA AA23-075A: LockBit 3.0](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a)
- [CISA AA23-165A: Understanding LockBit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)


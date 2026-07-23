---
layout: post
title: "Lumma Stealer 분석: ClickFix에서 브라우저 세션 탈취까지"
description: "Lumma MaaS의 전달 경로, 정보 탈취 대상, C2와 세션·Token 사고 대응"
date: 2025-05-21 13:40:00 +0900
permalink: /lumma-stealer-malware-analysis
categories: [Security, Malware]
tags: [lumma, infostealer, clickfix, maas, incident-response]
---

## 분석 요약

Lumma Stealer(LummaC2)는 affiliate가 builder와 관리 panel을 사용하는 Malware-as-a-Service다. 피싱·malvertising·가짜 CAPTCHA/ClickFix·정상 cloud service 악용으로 전달되며 Chromium·Mozilla 계열 브라우저, 암호화폐 지갑과 애플리케이션 데이터를 탈취한다.

비밀번호 재설정만으로 대응을 끝내면 안 된다. 브라우저 cookie와 refresh token이 탈취됐다면 MFA를 다시 거치지 않고 세션이 재사용될 수 있으므로 **세션 폐기와 OAuth/app token 회전**이 필요하다.

## 전달과 실행 체인

```text
malvertising / fake CAPTCHA / ClickFix
  └─ user copies command into Run/Terminal
      └─ mshta·PowerShell·script host
          └─ staged loader
              └─ Lumma
                  ├─ browser DB·cookies·wallets
                  ├─ HTTPS C2 exfiltration
                  └─ plugin / additional payload
```

ClickFix는 사용자가 명령을 직접 붙여넣기 때문에 전통적인 “악성 첨부파일” 탐지를 우회한다. 브라우저 직후 `powershell`, `mshta`, `wscript`, `cmd`가 시작되고 clipboard 기반 command가 실행되는 계보가 핵심이다.

```yaml
title: Browser Followed By Script Interpreter
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
  child:
    Image|endswith:
      - '\powershell.exe'
      - '\mshta.exe'
      - '\wscript.exe'
      - '\cmd.exe'
  condition: parent and child
```

브라우저가 직접 child process를 만들지 않는 ClickFix 변형도 있으므로 사용자 입력 직후의 RunMRU, PowerShell 4104, process start를 시간으로 연결한다.

## 기술적 특징

Microsoft 분석에 따르면 core는 C++·ASM 조합이며 LLVM 기반 control-flow flattening, dead code, stack encryption과 low-level syscall로 정적 분석을 방해한다. hardcoded C2 외에 Telegram과 Steam profile을 fallback으로 이용하고, HTTPS 뒤 Cloudflare를 사용해 origin을 숨길 수 있다.

version별 C2 형식은 달라지지만 설정 수신, 수집 데이터 전송, 추가 plugin 요청이라는 단계는 유지된다. 따라서 `act=receive_message` 같은 문자열 IOC 하나보다 다음을 결합한다.

- user-writable 경로의 unsigned binary
- browser profile·wallet directory 대량 접근
- 실행 직후 여러 신규 도메인으로 HTTPS POST
- Telegram/Steam profile 접근 뒤 이어지는 별도 C2
- clipboard stealer·coin miner 등 추가 module 생성

## 침해 조사

호스트에서 아래를 보존한다.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
```

- browser history, download history, Login Data/Cookies 접근 시각
- DPAPI 관련 이벤트와 사용자 profile 파일 접근
- cryptocurrency wallet extension·desktop wallet directory
- PowerShell, Run dialog, script host 실행 기록
- DNS·proxy·TLS telemetry와 업로드 byte
- 후속 payload·예약 작업·Run Key

브라우저 DB 파일을 직접 열어 조사할 때 원본 profile을 변경하지 않도록 forensic copy에서 작업한다.

## 계정·세션 대응

1. 감염 장치를 네트워크에서 격리한다.
2. 신뢰 가능한 별도 장치에서 모든 IdP·SaaS 세션을 폐기한다.
3. 비밀번호, refresh token, API key, wallet secret을 위험도에 따라 회전한다.
4. impossible travel, 신규 OAuth consent, mailbox rule, cloud API 호출을 헌팅한다.
5. clean image로 재구축한 뒤에만 사용자의 새 자격 증명을 입력한다.

같은 감염 장치에서 비밀번호를 바꾸면 새 값도 다시 탈취될 수 있다.

## 안전한 샘플 분석

실제 wallet이나 browser profile을 분석 VM에 넣지 않는다. 가짜 profile과 canary credential을 사용하고 outbound는 가상 DNS/HTTP service로 제한한다. Lumma의 anti-analysis 때문에 sandbox에서 행위가 없더라도 benign 판정하지 않는다. 정적 결과, memory artifact, host telemetry와 함께 판단한다.

## References

- [Microsoft: Lumma Stealer Technical Analysis](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Microsoft: ClickFix Analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)


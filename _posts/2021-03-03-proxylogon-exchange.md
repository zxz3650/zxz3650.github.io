---
layout: post
title: "ProxyLogon: Exchange Server 웹셸 침해 분석"
description: "CVE-2021-26855 체인의 원리와 Exchange 웹셸·후속 행위 조사 방법"
date: 2021-03-03 11:15:00 +0900
permalink: /proxylogon-exchange-incident-analysis
categories: [Security, Incident Response]
tags: [proxylogon, exchange, webshell, cve-2021-26855, poc]
---

## 공격 체인

ProxyLogon은 Exchange Proxy Architecture의 인증 경계를 우회하는 CVE-2021-26855와 후속 파일 쓰기 취약점을 연결해 인증 전 코드 실행으로 이어진 공격 체인이다. 실제 침해에서는 ASPX 웹셸을 설치해 패치 이후에도 접근을 유지했다.

## 침해 분석

- IIS·HttpProxy 로그의 `proxyLogon.ecp` 및 비정상 Autodiscover 요청
- OWA/ECP·`aspnet_client` 경로의 신규 ASPX
- `w3wp.exe → cmd.exe/powershell.exe` 프로세스 계보
- ProgramData의 ZIP·7z·RAR 파일과 메일 데이터 스테이징
- LSASS 접근, 신규 계정, PsExec·WMI 횡적 이동

패치 날짜 이전에 서버가 노출됐다면 현재 버전만 확인해서는 안 된다. 웹셸 생성 시간은 조작될 수 있으므로 MFT, USN Journal, IIS 로그를 교차 검증한다.

## 방어용 PoC·검증 도구

Microsoft의 [Test-ProxyLogon](https://microsoft.github.io/CSS-Exchange/Security/Test-ProxyLogon/)은 알려진 로그 패턴과 의심 파일을 수집하는 방어용 스크립트다.

```powershell
Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath C:\IR\ProxyLogon
```

결과의 압축 파일과 스크립트는 자동으로 악성 판정하지 말고 생성 주체와 업무 맥락을 검토한다. 공개 공격 exploit은 운영 Exchange에 실행하지 않는다.

## 대응

보안 업데이트, Microsoft Safety Scanner·EDR 검사, 웹셸 제거, 자격 증명 교체를 수행한다. 침해가 확인되면 Exchange 서버만 재설치하는 것으로 끝내지 말고 AD와 메일 접근 범위를 조사한다.

## References

- [DEVCORE ProxyLogon Research](https://proxylogon.com/)
- [Microsoft HAFNIUM Investigation](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)


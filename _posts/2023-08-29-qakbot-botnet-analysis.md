---
layout: post
title: "QakBot 분석: 봇넷 감염에서 랜섬웨어 초기 접근까지"
description: "QakBot의 이메일 유입, DLL 실행, C2·자격 증명 탈취와 침해 조사"
date: 2023-08-29 16:30:00 +0900
permalink: /qakbot-malware-botnet-analysis
categories: [Security, Malware]
tags: [qakbot, qbot, malware, botnet, ransomware]
---

## 분석 요약

QakBot(Qbot)은 금융정보 탈취 악성코드에서 발전해 다른 범죄조직에 감염 호스트 접근을 제공하는 loader·botnet 역할을 했다. 2023년 국제 공조로 당시 인프라가 제거됐지만, 과거 침해 조사에서는 QakBot 제거 사실과 **이미 배포된 후속 payload**를 구분해야 한다.

## 일반적인 실행 체인

캠페인에 따라 OneNote, PDF link, ZIP, HTML smuggling 등 유입 방식은 달랐다. 공통 분석점은 사용자가 내려받은 container와 그 안의 script가 DLL 실행으로 이어지는 계보다.

```text
malspam / hijacked thread
  └─ archive·OneNote·HTML·link
      └─ script or living-off-the-land binary
          └─ QakBot DLL
              ├─ browser/email credential theft
              ├─ C2 registration
              └─ Cobalt Strike / ransomware handoff
```

## 호스트 포렌식

다음 artifact를 최초 실행 시각 기준으로 수집한다.

- browser download history와 Zone.Identifier
- LNK·Jump List·RecentDocs
- Prefetch의 `RUNDLL32.EXE`, `REGSVR32.EXE`, `WSCRIPT.EXE`
- Amcache·Shimcache의 신규 DLL과 loader
- Run Key, scheduled task, service
- PowerShell Script Block log와 AMSI/EDR telemetry
- Outlook/메일 gateway의 원본 메시지와 동일 캠페인 수신자

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104
} | Where-Object Message -Match 'rundll32|regsvr32|FromBase64String|DownloadString'
```

`rundll32`는 정상 소프트웨어도 광범위하게 사용한다. user-writable 경로의 DLL, 이메일·브라우저 프로세스에서 시작된 계보, unsigned file, 신규 외부 연결을 함께 요구하면 오탐을 줄일 수 있다.

## 네트워크 분석

IP blocklist는 인프라 회전과 sinkhole 때문에 수명이 짧다. 다음 행위를 중심으로 본다.

- 사용자 단말에서 드물게 관측된 IP로 반복되는 encrypted beacon
- Office/browser 실행 직후 시작된 주기적 연결
- 같은 host에서 이어지는 Cobalt Strike 유사 beacon 또는 원격관리 도구
- 감염 이후 LDAP·SMB·RDP 탐색 증가

법 집행기관의 sinkhole·uninstaller 통신은 과거 C2 통신과 의미가 다를 수 있다. destination reputation만으로 시점을 혼동하지 말고 DNS·TLS·process telemetry를 결합한다.

## 사고 범위 결정

QakBot binary만 제거됐다고 사고가 끝난 것은 아니다. 다음 질문에 각각 증거로 답한다.

1. 어떤 사용자와 장치가 최초 문서를 실행했는가
2. 브라우저·메일·Windows 자격 증명이 접근됐는가
3. 후속 Cobalt Strike/RMM/ransomware가 배포됐는가
4. 동일한 피싱 thread가 내부·외부 연락처로 확산됐는가
5. 탈취 계정으로 VPN·cloud에 재접속했는가

## 안전한 분석

실제 QakBot sample을 업무용 VM이나 인터넷에 직접 연결된 sandbox에서 실행하지 않는다. 정적 분석과 기존 telemetry를 우선하고, 동적 분석은 sinkhole DNS·가상 서비스만 제공하는 격리망에서 수행한다. 메일 원본·내부 도메인·고객 정보가 포함된 sample은 공개 sandbox에 업로드하지 않는다.

## References

- [FBI: QakBot Infrastructure Takedown](https://www.fbi.gov/news/stories/fbi-partners-dismantle-qakbot-infrastructure-in-multinational-cyber-takedown)
- [MITRE ATT&CK: QakBot](https://attack.mitre.org/software/S0650/)


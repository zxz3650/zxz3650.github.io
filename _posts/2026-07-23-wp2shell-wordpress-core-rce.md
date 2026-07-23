---
layout: post
title: "wp2shell: WordPress Core Pre-Auth RCE 분석과 대응"
date: 2026-07-23 00:00:00 +0900
categories: [Security, Vulnerability]
tags: [wordpress, wp2shell, cve-2026-63030, cve-2026-60137, rce]
---

## TL;DR

**wp2shell**은 WordPress Core의 두 취약점, **CVE-2026-63030**과 **CVE-2026-60137**을 연결해 인증되지 않은 공격자가 원격 코드 실행(RCE)까지 도달할 수 있게 하는 공격 체인이다. 플러그인이나 테마가 없는 기본 설치도 영향받을 수 있다는 점이 특히 위험하다.

WordPress 6.9 계열은 **6.9.5 이상**, 7.0 계열은 **7.0.2 이상**으로 즉시 업데이트해야 한다. WordPress 6.8 계열은 체인의 SQL Injection 취약점에 대한 수정이 포함된 **6.8.6 이상**을 사용해야 한다.

> 공개 PoC가 존재하고 실제 악용이 확인된 상황이므로, 단순히 버전만 올리는 데서 끝내지 말고 업데이트 이전 침해 여부까지 확인해야 한다.

## 취약점 개요

wp2shell은 단일 취약점의 이름이 아니라 다음 두 문제를 결합한 공격 체인의 별칭이다.

| 구분 | 내용 |
|---|---|
| CVE-2026-63030 | REST API batch endpoint의 route confusion 문제 |
| CVE-2026-60137 | `WP_Query`의 `author__not_in` 처리 과정에서 발생하는 SQL Injection |
| 최종 영향 | 인증 없이 데이터 접근 및 조건에 따라 WordPress 사이트의 원격 코드 실행 |
| 심각도 | CVE-2026-63030 CNA 기준 CVSS 3.1 9.8 Critical |
| 공격 조건 | 네트워크 접근 가능, 사용자 인증 및 상호작용 불필요 |

핵심은 REST batch 요청의 내부 라우팅과 권한 판단을 혼동시켜 원래 외부 입력이 직접 도달해서는 안 되는 쿼리 경로를 열고, 이어지는 SQL Injection으로 데이터베이스 정보를 탈취하는 것이다. 공격자는 확보한 인증 정보를 악용해 관리자 권한을 획득한 뒤 WordPress의 파일 편집·업로드 기능 등을 통해 코드 실행으로 확장할 수 있다.

이 글은 방어 목적의 개요만 다루며, 재현 가능한 공격 요청이나 페이로드는 포함하지 않는다.

## 영향받는 버전

WordPress의 공식 보안 릴리스 기준은 다음과 같다.

- **WordPress 7.0.0–7.0.1:** 두 취약점의 영향을 받음. 7.0.2로 업데이트
- **WordPress 6.9.0–6.9.4:** 두 취약점의 영향을 받음. 6.9.5로 업데이트
- **WordPress 6.8.x:** CVE-2026-60137의 영향을 받음. 6.8.6으로 업데이트
- **WordPress 6.8 이전:** WordPress 공식 공지 기준 영향 없음
- **WordPress 7.1 beta:** 7.1 beta2에 수정 포함

실제 배포 환경에서는 배포판이나 호스팅 사업자가 백포트한 패치를 사용할 수 있으므로 표시 버전만 보지 말고 공급자의 보안 공지도 함께 확인해야 한다.

## 왜 위험한가

### 1. WordPress Core 취약점

일반적인 WordPress 사고는 오래된 플러그인이나 테마에서 시작되는 경우가 많다. wp2shell은 Core 자체의 문제이므로 플러그인이 없는 기본 설치도 공격 표면에 포함된다.

### 2. 인증이 필요하지 않음

인터넷에서 사이트에 접근할 수 있는 공격자가 로그인 없이 체인을 시작할 수 있다. 사용자 클릭도 요구하지 않아 자동화된 대규모 스캔과 악용에 적합하다.

### 3. 공개 PoC와 실제 악용

공개 PoC가 등장한 뒤 인터넷 전반의 스캔과 실제 악용 정황이 관측됐다. CISA도 CVE-2026-60137을 Known Exploited Vulnerabilities(KEV) Catalog에 추가했다. 따라서 “취약했지만 지금은 패치했다”는 사실만으로 안전을 보장할 수 없다.

## 즉시 대응

### 1. 업데이트

가장 먼저 WordPress Core를 지원되는 수정 버전으로 올린다.

```bash
wp core version
wp core update
wp core verify-checksums
```

WP-CLI를 사용할 수 없다면 관리자 화면의 **Dashboard → Updates**에서 업데이트하고, 호스팅 환경의 자동 업데이트 성공 여부도 확인한다.

### 2. 임시 차단

즉시 업데이트할 수 없는 짧은 시간 동안에는 WAF 또는 웹 서버에서 익명 사용자의 다음 batch API 접근을 차단할 수 있다.

- `/wp-json/batch/v1`
- `?rest_route=/batch/v1`

이는 긴급 완화책일 뿐 패치를 대체하지 않는다. 정상 REST API 기능에 영향을 줄 수 있으므로 적용 전 서비스 의존성을 확인한다.

### 3. 자격 증명 교체

취약 버전이 외부에 노출된 적이 있다면 다음을 교체한다.

- WordPress 관리자 및 편집자 계정 비밀번호
- 데이터베이스 계정 비밀번호
- 호스팅·SFTP·SSH·배포 계정 자격 증명
- `wp-config.php`의 Authentication Unique Keys and Salts
- 외부 서비스 API Key 및 플러그인에 저장된 비밀 값

비밀번호 교체 전 침해된 관리자 세션과 의심 계정을 먼저 차단해야 공격자의 재진입 가능성을 줄일 수 있다.

## 침해 점검 체크리스트

### 계정과 데이터베이스

- 최근 생성되거나 권한이 상승한 관리자 계정
- 기존 관리자의 이메일 주소·비밀번호·권한 변경
- `wp_users`, `wp_usermeta`, `wp_options`의 비정상 변경
- 예약 작업과 자동 로드 옵션에 삽입된 난독화 코드 또는 외부 URL

### 파일 시스템

- WordPress Core 무결성: `wp core verify-checksums`
- 플러그인 무결성: `wp plugin verify-checksums --all`
- 최근 수정된 PHP 파일과 업로드 디렉터리의 실행 가능한 파일
- 활성 테마의 `functions.php`, `404.php`, `header.php` 등 비정상 변경
- `wp-config.php`, `.htaccess`, 웹 서버 설정의 변조
- `wp-content/mu-plugins`와 알 수 없는 플러그인

예시 점검 명령은 시스템 상황에 맞게 범위를 조정한다.

```bash
find /var/www -type f -name '*.php' -mtime -14 -print
find /var/www -path '*/wp-content/uploads/*' -type f -name '*.php' -print
```

### 로그

다음 흔적을 웹 서버, WAF, CDN, WordPress 감사 로그에서 함께 확인한다.

- 취약 기간 중 REST batch endpoint 요청
- 비정상적으로 긴 쿼리 문자열 또는 반복적인 4xx/5xx 응답
- 알 수 없는 IP의 `wp-login.php`, `wp-admin` 접근
- 테마·플러그인 편집, 파일 업로드, 신규 관리자 생성 직전과 직후의 요청
- 웹 프로세스가 실행한 의심스러운 자식 프로세스와 외부 통신

로그가 없다고 침해가 없었다고 단정할 수 없다. 공격자가 로그를 삭제했거나 CDN/WAF와 원본 서버에 기록이 분산됐을 수 있다.

## 복구 원칙

침해가 확인되면 단순히 발견된 웹셸만 삭제하지 않는다.

1. 사이트를 격리하고 증거를 보존한다.
2. 신뢰 가능한 백업 또는 새 환경에서 WordPress Core를 재배포한다.
3. 플러그인과 테마를 공식 출처에서 다시 설치한다.
4. 데이터베이스에서 악성 계정, 예약 작업, 옵션 변조를 점검한다.
5. 관련 자격 증명과 salts를 모두 교체한다.
6. WAF·EDR·웹 로그를 기반으로 최초 침투 시점과 영향 범위를 조사한다.
7. 복구 후 파일 무결성 모니터링과 관리자 MFA를 활성화한다.

## 탐지와 예방 포인트

- WordPress Core 자동 보안 업데이트 활성화 및 성공 여부 모니터링
- 인터넷 노출 WordPress 자산과 버전의 지속적 인벤토리 관리
- 관리자 계정 MFA와 최소 권한 적용
- 관리자 화면의 파일 편집 기능 비활성화 검토: `DISALLOW_FILE_EDIT`
- 업로드 디렉터리의 PHP 실행 차단
- REST batch endpoint에 대한 WAF 로깅 및 비정상 요청 탐지
- Core·플러그인·테마의 변경 감시와 정기 무결성 검증
- 웹 프로세스의 외부 통신 및 셸 실행 모니터링

## 결론

wp2shell의 중요한 교훈은 “WordPress 보안은 플러그인 업데이트만으로 충분하지 않다”는 것이다. Core의 인증 전 공격 표면이 무너지면 기본 설치도 직접적인 위험에 놓인다.

우선순위는 명확하다.

1. 수정 버전으로 즉시 업데이트
2. 취약 기간의 REST batch 요청과 관리자 활동 조사
3. 파일·DB·계정 무결성 확인
4. 노출 이력이 있다면 자격 증명 교체와 사고 대응 수행

## 참고 자료

- [WordPress 7.0.2 Security Release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [CVE-2026-63030 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63030)
- [CVE-2026-60137 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60137)
- [wp2shell: Pre Authentication RCE in WordPress Core — Searchlight Cyber](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/)
- [wp2shell Incident Response Guide — Eye Research](https://labs.eye.security/wp2shell-defenders-guide/)

---

*본 문서는 승인된 환경의 방어와 사고 대응을 위한 자료다. 취약점 검증은 반드시 소유하거나 명시적으로 허가받은 시스템에서만 수행해야 한다.*

---
layout: post
title: "Shannon 엔트로피를 활용한 자료유출 조사"
description: "DNS·HTTP·파일의 엔트로피를 계산하고 기준선·전송 행위와 결합하는 실전 포렌식 및 Splunk 헌팅"
date: 2024-08-20 14:30:00 +0900
last_modified_at: 2026-07-23 22:00:00 +0900
permalink: /shannon-entropy-data-exfiltration
categories: [Security, Threat Hunting]
tags: [shannon-entropy, data-exfiltration, dns, splunk, dfir]
---

## TL;DR

Shannon 엔트로피는 문자열이나 바이트 분포가 얼마나 예측하기 어려운지를 수치화한다. 압축·암호화·인코딩된 자료는 자연어보다 높은 엔트로피를 보이는 경우가 많아 DNS tunnel, 비정상 HTTP parameter, staging archive 탐색에 유용하다.

그러나 **높은 엔트로피는 자료유출의 증거가 아니다.** 정상적인 UUID, CDN, tracking ID, 암호화 파일도 높은 값을 가진다. 반대로 공격자가 padding이나 사전 기반 encoding을 사용하면 낮은 엔트로피로 유출할 수 있다.

실전 판정은 다음처럼 해야 한다.

```text
entropy
  + length·volume
  + repetition·time window
  + destination prevalence
  + process·user·asset context
  + actual egress evidence
  = investigation priority
```

## 1. Shannon 엔트로피란 무엇인가

이산 확률변수의 Shannon 엔트로피는 다음과 같다.

```text
H(X) = - Σ p(xᵢ) × log₂ p(xᵢ)
```

문자열 `aaaaaa`는 한 종류의 문자만 나오므로 엔트로피가 0이다. 여러 문자가 비슷한 비율로 나타날수록 값이 커진다.

문자열의 문자 분포를 측정하면 단위는 대체로 `bits/character`, 파일의 256개 byte 값 분포를 측정하면 범위는 0–8 `bits/byte`다.

중요한 주의점:

- 값은 계산 alphabet과 단위에 따라 달라 직접 비교 조건을 맞춰야 한다.
- 짧은 문자열은 가능한 문자 종류가 제한돼 추정치가 불안정하다.
- 엔트로피는 문자 순서를 보지 않는다. `abcabc`와 `cbacba`는 같은 문자 빈도면 같은 값이다.
- 평균 엔트로피는 파일 내부의 작은 고엔트로피 구간을 숨길 수 있다.
- encoding은 엔트로피와 길이를 함께 변화시킨다.

따라서 “4.0 이상이면 악성” 같은 전역 threshold는 사용하지 않는다.

## 2. 분석용 Python 계산기

아래 코드는 문자열 또는 파일의 byte entropy를 계산한다. 탐지 PoC가 아니라 수집한 증거를 비파괴적으로 측정하는 도구다.

```python
#!/usr/bin/env python3
import argparse
import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    counts = Counter(data)
    return -sum(
        (count / size) * math.log2(count / size)
        for count in counts.values()
    )


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--text")
group.add_argument("--file", type=Path)
args = parser.parse_args()

if args.text is not None:
    payload = args.text.encode("utf-8")
    source = "text"
else:
    payload = args.file.read_bytes()
    source = str(args.file)

print(f"source={source}")
print(f"bytes={len(payload)}")
print(f"entropy_bits_per_byte={shannon_entropy(payload):.4f}")
```

실행 예:

```bash
python3 entropy.py --text 'normal-hostname'
python3 entropy.py --file suspicious.bin
shasum -a 256 suspicious.bin
```

파일 원본은 읽기 전용 forensic copy에서 다루고 entropy, 크기, SHA-256, MIME/매직 바이트를 함께 기록한다.

## 3. 파일 엔트로피로 staging을 조사한다

자료유출 전에 파일을 ZIP·7z·RAR로 묶거나 암호화하면 byte 분포가 균등해져 높은 엔트로피를 보일 수 있다. 하지만 JPEG, MP4, 정상 소프트웨어 package도 동일하다.

파일 조사는 다음 순서가 안전하다.

1. 파일의 실제 형식과 확장자가 일치하는지 확인한다.
2. 전체 entropy와 고정 크기 block별 entropy를 계산한다.
3. 생성 프로세스와 명령행을 확인한다.
4. 생성 직전 대량 파일 읽기와 생성 직후 egress를 연결한다.
5. archive 내부 목록은 추출하지 않고 먼저 list-only 옵션으로 확인한다.

64 KiB block별 측정 예:

```python
BLOCK = 64 * 1024
with open("suspicious.bin", "rb") as handle:
    offset = 0
    while chunk := handle.read(BLOCK):
        print(offset, len(chunk), f"{shannon_entropy(chunk):.4f}")
        offset += len(chunk)
```

PE 파일에서 일부 section만 높은 경우 packer·암호화된 configuration일 수 있다. 이것만으로 악성이라고 판정하지 않고 signer, import, section permission, 실행 행위를 함께 본다.

### 강한 상관관계

```text
office/file server의 대량 read
  → 7z/rar/powershell archive 생성
  → user-writable 또는 staging directory
  → 고엔트로피 대용량 파일
  → cloud storage/신규 외부 IP로 upload
```

이 연결이 입증되면 entropy는 “암호화·압축 가능성”을 보강하는 증거가 된다.

## 4. DNS 자료유출에서 무엇을 측정할까

DNS tunnel은 자료를 작은 chunk로 나눠 공격자가 관리하는 도메인의 subdomain label에 넣는다.

```text
<sequence>.<encoded-data>.<attacker-domain>
```

Base32·Base64url·hex 또는 맞춤 encoding을 사용하면 label이 길고 다양해질 수 있다. 한 번의 질의보다 `src + registered_domain + time window`로 집계한다.

유용한 feature:

| Feature | 의미 |
|---|---|
| `left_label_len` | subdomain payload 길이 |
| `entropy` | 문자 분포의 불확실성 |
| `unique_label_count` | chunk가 계속 변하는지 |
| `queries_per_minute` | beacon/tunnel 전송률 |
| `NXDOMAIN ratio` | authoritative 처리 실패·DGA 가능성 |
| `qtype` | TXT·NULL·A·AAAA 사용 양상 |
| `src_count` | 단일 감염 호스트인지 정상 서비스인지 |
| `domain prevalence` | 조직에서 처음 보는 목적지인지 |

등록 도메인은 단순히 마지막 두 label로 자르면 안 된다. `co.uk` 같은 public suffix가 있으므로 PSL-aware parser 또는 DNS Add-on에서 정규화한 field를 사용한다.

## 5. Splunk에서 1차 후보를 줄인다

먼저 계산 비용이 싼 길이·빈도·고유값으로 후보를 좁힌다. 필드명은 환경에 맞게 변경한다.

```spl
index=dns earliest=-24h
| eval query=lower(trim(query,"."))
| eval left_label=mvindex(split(query,"."),0),
       left_label_len=len(left_label)
| where left_label_len >= 20
| bin _time span=10m
| stats count dc(left_label) AS unique_labels
        avg(left_label_len) AS avg_len
        max(left_label_len) AS max_len
        values(record_type) AS qtypes
  BY _time src registered_domain
| where count >= 20 AND unique_labels >= 15
| sort - unique_labels max_len
```

이 단계는 entropy를 계산하기 전에 대량 정상 DNS를 제거한다. `registered_domain`이 없다면 lookup이나 PSL 기반 extraction을 먼저 구현한다.

## 6. SPL만으로 Shannon 엔트로피 계산하기

Splunk에 entropy command가 없는 환경에서는 문자를 행으로 펼쳐 직접 계산할 수 있다. 이 방식은 비용이 크므로 반드시 앞 단계에서 후보를 제한한다.

```spl
index=dns earliest=-1h
| eval query=lower(trim(query,".")),
       left_label=mvindex(split(query,"."),0),
       label_len=len(left_label)
| where label_len >= 20
| streamstats count AS row_id
| rex field=left_label max_match=0 "(?<symbol>.)"
| mvexpand symbol
| stats count AS frequency
        first(query) AS query
        first(src) AS src
        first(registered_domain) AS registered_domain
        first(label_len) AS label_len
  BY row_id left_label symbol
| eventstats sum(frequency) AS total BY row_id
| eval probability=frequency/total,
       entropy_term=-probability*log(probability,2)
| stats sum(entropy_term) AS entropy
        first(query) AS query
        first(src) AS src
        first(registered_domain) AS registered_domain
        first(label_len) AS label_len
  BY row_id left_label
| where entropy >= 3.5
| sort - entropy label_len
```

`3.5`는 예시일 뿐이다. 조직의 정상 DNS로 분포를 만들고 label 길이 구간별 percentile을 사용해야 한다. 10자 label과 50자 label의 raw entropy를 같은 기준으로 비교하면 편향된다.

URL Toolbox 같은 검증된 Splunk app 또는 외부 enrichment가 있다면 계산을 그쪽에서 수행하고 SPL에서는 집계에 집중하는 편이 효율적이다.

## 7. 고정 threshold 대신 기준선을 만든다

정상 데이터를 2–4주 수집해 `registered_domain`, asset role, label length bucket별 기준선을 만든다.

```spl
index=dns earliest=-30d@d latest=-1d@d
| eval query=lower(trim(query,".")),
       left_label=mvindex(split(query,"."),0),
       label_len=len(left_label),
       len_bucket=case(
         label_len<20,"00-19",
         label_len<40,"20-39",
         label_len<60,"40-59",
         true(),"60+"
       )
| stats count dc(left_label) AS unique_labels
  BY src registered_domain len_bucket
| eventstats perc95(unique_labels) AS p95_unique
  BY registered_domain len_bucket
| where unique_labels > p95_unique
```

실제 운영에서는 계산해 둔 entropy field를 포함해 `p95` 또는 `p99`를 만든다. 기준선에 이미 침해 트래픽이 섞일 수 있으므로 초기 기간을 무조건 정상으로 신뢰하지 않는다.

### Peer group

- Domain Controller와 사용자 PC
- CI/CD runner와 사무용 단말
- DNS resolver와 직접 질의 client
- 보안 scanner와 일반 서버

역할이 다른 자산을 같은 분포로 비교하지 않는다.

## 8. HTTP·URL parameter에 적용하기

자료가 query string, cookie, POST field, URI path에 encoding될 수도 있다. URL 전체 entropy를 계산하면 scheme·domain·path가 섞여 의미가 약해진다. 의심 parameter 값을 분리해 측정한다.

```text
long parameter
AND high entropy
AND repeated POST
AND increasing bytes_out
AND rare destination
AND suspicious parent process
```

정상 JWT, SAML, analytics ID, cache key, signed URL은 대표적인 오탐이다. parameter name, destination application, token 구조와 정상 client를 기준으로 제외한다.

TLS 때문에 payload를 보지 못한다면 다음 metadata를 결합한다.

- SNI/registered domain과 최초 관측 시각
- client process·user·asset
- outbound bytes와 request cadence
- JA4/인증서/ASN 등 TLS context
- EDR의 file read와 socket 연결

## 9. 조사 쿼리: DNS 후보에서 호스트 행위로 이동

의심 source가 정해지면 DNS만 계속 보지 않고 endpoint·proxy·file telemetry를 시간으로 연결한다.

```spl
(
  index=dns earliest=-2h latest=now src="<suspect_ip>"
)
OR (
  index=endpoint earliest=-2h latest=now
  (src_ip="<suspect_ip>" OR host="<suspect_host>")
)
OR (
  index=proxy earliest=-2h latest=now src_ip="<suspect_ip>"
)
| eval activity=coalesce(process_name,query,url,action),
       remote=coalesce(registered_domain,dest_domain,dest_ip)
| table _time index sourcetype host user activity remote
        process_name parent_process_name bytes_out
| sort 0 _time
```

찾아야 할 연결:

1. 민감 디렉터리의 대량 파일 접근
2. archive 또는 임시 파일 생성
3. `nslookup`, PowerShell, Python, custom binary 실행
4. DNS 질의율·label 길이·entropy 상승
5. 동일 호스트의 HTTPS·cloud upload
6. 파일 삭제와 로그 정리

## 10. 엔트로피 기반 판정 매트릭스

| Entropy | 행위 Context | 판단 |
|---|---|---|
| 높음 | 정상 CDN·업데이트, 다수 자산 | 정상 가능성 높음 |
| 높음 | 단일 호스트, 신규 도메인, 긴 고유 label 반복 | DNS tunnel 우선 조사 |
| 높음 | archive 생성 후 대량 egress | staging·유출 가능성 |
| 낮음 | 고정된 짧은 beacon | C2 가능, entropy로 미탐 |
| 낮음 | 단어 목록·padding 기반 encoding | 우회 가능, 빈도·volume 확인 |

엔트로피는 verdict가 아니라 triage feature다.

## 11. 오탐과 미탐

### 대표적 오탐

- CDN·telemetry·광고·tracking domain
- DKIM, ACME challenge와 service discovery
- UUID·hash·JWT·signed URL
- 백업·소프트웨어 배포 archive
- 정상 VPN·TLS 암호화 트래픽

### 대표적 미탐

- 낮은 속도의 DNS 유출
- 사전 단어를 사용하는 encoding
- 여러 도메인으로 분산된 chunk
- 정상 SaaS API를 통한 업로드
- padding으로 문자 분포를 인위적으로 변경
- DoH/DoT로 DNS sensor를 우회

DoH가 허용된다면 승인 resolver의 endpoint와 IP를 관리하고, 미승인 DoH destination·browser policy 위반을 별도로 탐지한다.

## 12. 증거와 보고서 작성

보고서에 “entropy가 높아 유출됐다”고 쓰지 않는다. 다음을 분리한다.

- **관측 사실:** label 평균 길이, entropy 분포, query 수, bytes, 시간대
- **비교 근거:** 동일 자산의 과거, peer group, domain prevalence
- **상관 증거:** 파일 접근·archive 생성·process·egress
- **해석:** 압축·암호화된 chunk 전송과 일치
- **대안 설명:** 정상 telemetry·CDN·backup 가능성
- **결론 신뢰도:** confirmed / probable / possible / insufficient

실제 자료유출 확정에는 전송된 내용, destination 소유권, server-side log, DLP·CASB, packet capture 또는 공격자 인프라 등 추가 증거가 필요할 수 있다.

## 13. 운영 체크리스트

- [ ] 계산 대상과 alphabet·단위를 통일했는가
- [ ] 짧은 문자열을 별도 처리했는가
- [ ] entropy를 길이·빈도·volume과 결합했는가
- [ ] 등록 도메인을 PSL 기준으로 계산했는가
- [ ] 자산 역할별 peer group을 사용했는가
- [ ] 정상 CDN·JWT·backup 오탐을 검토했는가
- [ ] DNS에서 endpoint·proxy·file timeline으로 이동했는가
- [ ] 자동 차단 전 analyst 검증과 rollback이 있는가
- [ ] 원본 로그, 쿼리, time range, lookup version을 보존했는가

## References

- [Claude Shannon, A Mathematical Theory of Communication](https://ieeexplore.ieee.org/document/6773024)
- [MITRE ATT&CK T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [Splunk: Detecting DNS Exfiltration](https://www.splunk.com/en_us/blog/security/detect-hunt-dns-exfiltration.html)
- [Splunk: Shannon Entropy and DNS](https://www.splunk.com/en_us/blog/security/random-words-on-entropy-and-dns.html)
- [Splunk Security Content: Exfiltration Detections](https://research.splunk.com/detections/tactics/exfiltration/)

---

엔트로피 분석은 방어와 사고 대응을 위한 통계적 보조 수단이다. 임계값은 다른 조직의 값을 복사하지 말고 자체 정상 데이터와 검증된 공격 시뮬레이션으로 조정한다.

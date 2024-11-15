# Understanding the MITRE ATT&CK TTPs: A Breakdown of Lapsus$ Attack Techniques

Lapsus$는 유명한 사이버 공격 그룹으로, 고도로 공공화된 사이버 공격을 통해 잘 알려져 있습니다. 이들은 다양한 전술, 기술, 절차(TTP)를 활용하여 표적 조직의 민감한 데이터를 침해, 확장, 유출합니다. 본 글에서는 Lapsus$의 MITRE ATT&CK 프레임워크에 따른 주요 TTP를 분석하여 사이버 보안 전문가들이 이러한 위험을 이해하고 완화하는 데 도움을 드리고자 합니다.

---

## MITRE ATT&CK Tactics and Techniques

MITRE ATT&CK 프레임워크는 사이버 공격 행동을 여러 **Tactics**(전술) 및 **Techniques**(기법)으로 분류합니다. 아래는 Lapsus$ 그룹과 관련된 주요 TTP를 공격의 여러 단계에 따라 정리한 내용입니다.

### 1. **Initial Access (TA0001)**
   - **T1078 - Valid Accounts**: 도용되거나 재사용된 자격 증명을 이용해 무단 접근을 시도
   - **T1133 - External Remote Services**: 원격 서비스를 악용해 초기 접근 확보
   - **T1190 - Exploit Public-Facing Application**: 공개된 애플리케이션의 취약점을 공략해 접근 시도
   - **T1199 - Trusted Relationship**: 제3자의 신뢰 관계를 이용해 네트워크 침투

### 2. **Execution (TA0002)**
   - **T1059 - Command and Scripting Interpreter**
     - **T1059/001 - PowerShell**: PowerShell 스크립트를 통해 악성 명령 실행
     - **T1059/003 - Windows Command Shell**: 명령어 인터프리터를 다양한 작업에 활용
     - **T1059/004 - Unix Shell**: Unix 기반 환경에서 명령 실행

### 3. **Persistence (TA0003)**
   - **T1078 - Valid Accounts**: 도용된 자격 증명을 통해 지속적인 접근 유지
   - **T1078/002 - Domain Accounts**: 도메인 계정을 통한 접근 지속
   - **T1078/004 - Cloud Accounts**: 클라우드 계정을 이용한 장기적 접근
   - **T1021 - Remote Services**
     - **T1021/001 - Remote Desktop Protocol**: RDP를 통해 시스템에 지속적으로 접근
   - **T1114 - Email Collection**
     - **T1114/003 - Email Forwarding Rule**: 이메일 계정에서 정보를 유출하기 위해 이메일 포워딩 규칙 설정

### 4. **Privilege Escalation (TA0004)**
   - **T1068 - Exploitation for Privilege Escalation**: 취약점을 이용하여 권한 상승 시도
   - **T1078 - Valid Accounts**: 높은 권한을 가진 유효 계정 사용
   - **CVE-2021-34484**: 특정 취약점을 이용해 권한 상승

### 5. **Defense Evasion (TA0005)**
   - **T1070 - Indicator Removal on Host**: 탐지를 피하기 위해 작업 은폐
   - **T1562 - Impair Defenses**
     - **T1562/001 - Disable or Modify Tools**: 보안 도구 비활성화
   - **T1027 - Obfuscated Files or Information**: 파일이나 스크립트를 위장하여 탐지 회피
   - **T1535 - Subvert Trust Controls**: 신뢰 관계를 우회하여 무단 접근

### 6. **Credential Access (TA0006)**
   - **T1003 - OS Credential Dumping**
     - **T1003/001 - LSASS Memory**: LSASS 프로세스 메모리에서 자격 증명 추출
     - **T1003/002 - Mimikatz**: Mimikatz 도구를 사용해 자격 증명 추출
   - **T1110 - Brute Force**: 무차별 공격으로 자격 증명 획득 시도
   - **T1110/002 - Password Cracking**: 해시된 비밀번호를 해독해 무단 접근

### 7. **Discovery (TA0007)**
   - **T1082 - System Information Discovery**: 시스템 정보를 수집하여 추가 작업 준비
   - **T1201 - Remote Services**: 원격 서비스 식별 및 악용 가능성 탐색

### 8. **Lateral Movement (TA0008)**
   - **T1078 - Valid Accounts**: 도용된 자격 증명을 사용하여 네트워크 내 이동
   - **T1078/002 - Domain Accounts**: 도메인 자격 증명을 사용해 추가 시스템 접근

### 9. **Collection (TA0009)**
   - **T1114 - Email Collection**: 이메일 계정에서 데이터 수집
   - **T1537 - Transfer Data to Cloud Account**: 수집한 데이터를 클라우드 스토리지로 전송

### 10. **Exfiltration (TA0010)**
   - **T1114 - Email Collection**
     - **T1114/003 - Email Forwarding Rule**: 이메일을 통해 민감한 데이터 유출

---

## 주요 관찰 사항

Lapsus$는 **자격 증명 도용**, **공개 애플리케이션 취약점 공격**, **신뢰 관계 남용**을 통한 초기 접근을 자주 사용합니다. 이들은 **유효한 계정을 통해 접근을 지속**하며, 취약점 악용을 통한 **권한 상승**과 보안 도구 비활성화로 **방어 회피**를 시도합니다.

### 감지해야 할 침해 지표 (IOCs)
- 클라우드 플랫폼 및 원격 서비스에서의 **비정상 계정 활동**
- 기업 이메일 계정에서의 **의심스러운 이메일 포워딩 규칙**
- **비정상적인 PowerShell 및 Command Shell** 실행
- **위장된 스크립트** 또는 보안 도구 및 설정 변경

## 방어를 위한 권장 사항

Lapsus$ 및 유사한 위협 행위자로부터 보호하기 위해:
1. **다중 인증(MFA)**을 모든 계정, 특히 권한이 높은 계정에 적용
2. **이메일 포워딩 규칙 정기 검토** 및 무단 구성 감지
3. **PowerShell 및 Command Shell 활동 모니터링**으로 악용 여부 확인
4. **엔드포인트 탐지 및 대응(EDR)** 도구 배포로 자격 증명 덤핑 방지
5. 특히 권한 상승으로 이어질 수 있는 **취약점 신속 패치**

---

Lapsus$의 TTP 분석을 통해 조직은 탐지 및 완화 전략을 개선할 수 있습니다. 보안 전문가들은 전방위적 방어 접근법을 채택하여 이러한 복합적인 공격에 대비해야 합니다.

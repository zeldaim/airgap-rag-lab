# 토폴로지 — 레포 지도 · 목표 구조 · 실행 구조

내 레포 전체를 보고 정리한 지도다. 각 그림은 **각 레포의 README·compose·문서에서 읽은 것**만 그렸고, 읽어서 확인하지 못한 관계는 맨 아래 "확인하지 못한 것"에 따로 적었다.
GitHub 에서 Mermaid 로 렌더링된다. 실선 = 지금 있음, 점선 = 아직 없음(계획).

## 1. 레포 지도 — 누가 누구에게 무엇을 주나

```mermaid
flowchart LR
  subgraph LAB["랩 · 데이터가 나오는 곳"]
    HSL["home-soc-lab<br/>Wazuh · ELK · Kali · Win VM"]
    ZEN["wazuh-slack-alertbot<br/>Wazuh 알림 + 엔트로피 탐지"]
    ADL["api-defense-lab<br/>DVRA · nginx · 탐지기 · 채점기"]
    TPL["traffic-persona-lab<br/>명세 기반 트래픽 생성기"]
    RTU["reservoir-rtu-lab<br/>ESP32 RTU + 관제 서버"]
    AQF["aquaflow-pipeline · aquaflow-data<br/>K-water 수질 · 수위 · 강수량"]
  end

  subgraph STD["표준 · 룰 · ML"]
    ASC["api-security-supply-chain<br/>API-BOM · 룰 자동 생성 · 대응 설계"]
    MLD["ml_detection<br/>IF · LOF · Autoencoder · RF"]
  end

  subgraph AI["AI 계층"]
    RAG["airgap-rag-lab<br/>로컬 LLM · RAG · 트리아지 · 보안 시험"]
    RF["룰 공장<br/>api-defense-lab/tools/rule_factory.py"]
  end

  ASC -->|"설계를 compose 한 번으로 재현"| ADL
  TPL -->|"독립 평가용 정상 트래픽"| ADL
  ASC -->|"Wazuh 룰 파일 · 문서를 코퍼스로"| RAG
  HSL -->|"탐지 문서를 코퍼스로"| RAG
  ADL -->|"라벨 있는 채점 결과 · ML 이벤트"| RAG
  ASC -->|"실행 이벤트 live_demo"| RAG
  ADL -->|"라벨 로그로 룰 채점"| RF
  RAG -->|"로컬 LLM(Ollama) 제공"| RF
  RTU -.->|"같은 원칙: 판정은 LLM 이 아니라 코드<br/>risk_floor"| RAG
  AQF -.->|"정상 패턴 학습 데이터"| RTU
  AQF -.->|"어댑터(계획)"| RAG
  RTU -.->|"어댑터(계획)"| RAG
  MLD -.->|"행위 ML 계열(설계 · 모델 카드)"| ADL
  ZEN -.->|"Wazuh 알림 연동(참고)"| HSL

  classDef planned stroke-dasharray: 5 5
  class RF planned
```

참고(별도 주제): `enterprise-network-lab`(Packet Tracer 멀티 사이트 네트워크), `pfsense-openvpn-acl-lab`(pfSense VPN·ACL), `multicloud-dr-petclinic`, `openssf-study` — AI SecOps 와 직접 연결되지는 않는다.

## 2. 목표 구조 — AI SecOps 의 논리 토폴로지 (현재 상태 표시)

설계 원칙(이 랩의 측정 결과에서 나옴): **LLM 은 제안·설명만 하고 판정과 실행은 코드가 한다.** 변경 조치는 사람 승인(HITL)을 거친다.

```mermaid
flowchart TB
  subgraph IN["① 수집 · 정규화"]
    A1["Wazuh 룰 알럿 어댑터<br/>있음"]
    A2["방어연습장 ML 이벤트 어댑터<br/>1차"]
    A3["aquaflow 수질 · 수위 어댑터<br/>계획"]
    A4["RTU 사건 어댑터<br/>계획"]
    SCH["공통 알럿 스키마<br/>없음"]
    A1 --> SCH
    A2 --> SCH
    A3 --> SCH
    A4 --> SCH
  end

  subgraph CTX["② 자산 컨텍스트"]
    B1["API-BOM · Shadow API 탐지<br/>있음(다른 레포)"]
    B2["SBOM · 취약점 스캔 · 서명<br/>있음"]
    B3["무결성 매니페스트<br/>모델 다이제스트 · 코퍼스 해시<br/>있음"]
    B4["AI-BOM<br/>없음"]
    B5["허용 목록 · 강수량 · 정책값<br/>있음 · 일부"]
  end

  subgraph AG["③ 에이전트 오케스트레이터 — 아직 없음"]
    C1["결정론 도구 호출<br/>룰 조회 · 명세 대조 · 후속 룰 · 허용 목록"]
    C2["RAG · 권한 필터 적용<br/>양쪽 검색기 앞단"]
    C3["LLM: 설명 · 요약만"]
    C4["판정 = 점수 규칙(코드)"]
  end

  GATE["④ 정책 게이트<br/>자동 허용 · 사람 승인 큐 · 금지<br/>없음"]
  PB["⑤ 대응 플레이북<br/>차단 목록 · 안전 모드 · 알림<br/>부분: 연습장 정책 · RTU 단계 7 미완"]
  LOG["⑥ 기록 · 검증<br/>근거 로그 · 서명 · sec_eval<br/>있음"]
  FB["오탐 피드백 → 룰 · 모델 재학습<br/>없음(사람이 손으로)"]

  SCH --> C1
  CTX --> C1
  C1 --> C4
  C2 --> C3
  C3 --> C4
  C4 --> GATE
  GATE --> PB
  PB --> LOG
  C4 --> LOG
  LOG -.-> FB

  classDef planned stroke-dasharray: 5 5
  class A3,A4,SCH,B4,C1,C2,C3,C4,GATE,FB planned
```

지금 흩어져 있는 구현: 트리아지 스크립트(`rag/triage.py`, `triage_ml.py`) · 룰 공장 · 보안 시험 하네스(`rag/sec_eval.py`) · 무결성·서명 도구가 각각 따로 돈다. ③과 ④(오케스트레이터와 정책 게이트)가 이어 붙일 자리다.

## 3. 실행 토폴로지 — 컨테이너 · 네트워크 · 신뢰 경계

### 3-1. airgap-rag-lab (`docker-compose.yml`)

```mermaid
flowchart TB
  subgraph HOST["호스트 · Windows 11 · RTX 5060 Laptop 8GB · Docker Desktop(WSL2, VM 메모리 7.5GB)"]
    subgraph NET["도커 네트워크 airgap — internal: true · 기본 게이트웨이 없음 · 외부로 못 나감"]
      OLL["ollama<br/>qwen2.5:7b-instruct · bge-m3<br/>GPU 연결 · 호스트 포트 없음"]
      APP["app<br/>rag · llm · tools<br/>chromadb 프로세스 안 PersistentClient"]
    end
    V1[("volume ollama_models<br/>외부 볼륨 · 모델")]
    V2[("volume chroma_data<br/>인덱스 · 평가 결과")]
    B1["bind mount 읽기 전용<br/>corpus · corpus_ml · samples · rag · llm"]
    B2["bind mount 쓰기<br/>integrity/"]
    GPU{{"NVIDIA GPU 장치"}}
  end
  NETX(("인터넷"))

  APP -->|"/api/chat · /api/embed"| OLL
  OLL --- V1
  APP --- V2
  APP --- B1
  APP --- B2
  OLL --- GPU
  NETX -. "빌드 · 모델 내려받기 때만<br/>실행 중에는 막힘" .-> HOST
```

신뢰 경계: ① `airgap` 네트워크 밖으로 나가는 경로가 없다(`llm/verify_airgap.py` 로 확인: `Network is unreachable`). ② 모델과 패키지는 빌드 시점에만 인터넷에서 오고, 다이제스트·해시로 고정하고 서명한다(`supply-chain/`). ③ **알럿·로그 필드는 신뢰할 수 없는 입력**이다(공격자가 만든 문자열) — 프롬프트에서 데이터로 표시하고 길이를 제한한다(인젝션 시험에서 이것만으로는 못 막음, `docs/evidence/14`).

### 3-2. api-defense-lab (`docker-compose.yml`)

```mermaid
flowchart LR
  subgraph TOOLS["profile tools"]
    TR["traffic<br/>합성 트래픽 · 라벨"]
    SC["scorer<br/>채점 · HTML 보고서"]
    TN["trainer<br/>ML 학습"]
  end
  subgraph CORE["core · 모든 포트는 127.0.0.1 에만 연다"]
    NG["nginx :8089<br/>접속 로그 · 차단 목록 403"]
    DW["dvra-web<br/>일부러 취약한 앱"]
    DB[("dvra-db<br/>postgres 15.4")]
    DT["detector<br/>Sigma 엔진 + ML 창 채점<br/>events.jsonl · ips.map"]
  end
  subgraph OPT["선택 모듈"]
    WZ["wazuh · profile wazuh<br/>SIEM 룰 작성"]
    ES[("elasticsearch · profile dashboard")]
    GF["grafana :3000 · profile dashboard"]
    IV["inventory · profile inventory<br/>API 목록 3방식"]
  end

  TR -->|"요청"| NG
  NG --> DW
  DW --> DB
  NG -->|"access.log"| DT
  DT -->|"ips.map 차단 결정"| NG
  DT -->|"events.jsonl"| SC
  TR -->|"labels.jsonl 정답지"| SC
  NG -.->|"로그"| WZ
  DT -.-> ES
  ES -.-> GF
  NG -.-> IV
  TN -->|"모델"| DT
```

### 3-3. reservoir-rtu-lab (`server/docker-compose.yml` + 펌웨어)

```mermaid
flowchart LR
  subgraph FIELD["현장 · Wokwi 시뮬레이터 (실제 시설 아님)"]
    ESP["ESP32 RTU · FreeRTOS<br/>출입통제 PIN · 수위 · 밸브 · 펌프<br/>사건 기록 HMAC 서명 · 서명된 업데이트(계획)"]
  end
  subgraph SRV["관제 서버 · PC · Docker"]
    TUN["cloudflared<br/>profile tunnel · 시연 때만"]
    NGX["nginx 127.0.0.1:8090<br/>레이트 리밋 · 차단 목록"]
    API["api · FastAPI<br/>BOLA 시연·수정 · 탐지 룰 + ML<br/>AI 사고 리포트: Claude · 로컬 Ollama · 규칙<br/>risk_floor: 판정 하한을 코드로"]
    DAT[("volume rtu-data")]
  end
  INET(("인터넷"))

  ESP -->|"HTTPS 사건 전송"| INET
  INET --> TUN
  TUN --> NGX
  NGX --> API
  API --- DAT
  API -.->|"자동 대응 · 안전 모드(단계 7, 미완)"| ESP
```

### 3-4. aquaflow (`docker-compose.yml` + GitHub Actions)

```mermaid
flowchart LR
  subgraph SRC["공공데이터 · data.go.kr"]
    K1["K-water 수질(시간)"]
    K2["K-water 수위(시간)"]
    K3["기상청 ASOS 강수량(D-1)"]
  end
  subgraph PIPE["aquaflow-pipeline"]
    COL["collector · 매시간 · 최근 6시간 겹쳐 수집"]
    Q["품질 검증<br/>격리: 불가능 값 · 중복 · 미래 시각<br/>표시: 기준 이탈 · 급변"]
    ORC["ORC 날짜별 파티션"]
    S3[("LocalStack S3<br/>저장 시 암호화")]
    DD["DuckDB 조회"]
  end
  GHA["GitHub Actions · 매시간"]
  DATA[("aquaflow-data · 비공개 레포<br/>ORC 커밋")]

  K1 --> COL
  K2 --> COL
  K3 --> COL
  COL --> Q
  Q --> ORC
  ORC --> S3
  ORC --> DD
  Q -->|"새 표시 행만 알림"| ALR["웹훅 알림"]
  GHA --> COL
  GHA -->|"커밋"| DATA
```

### 3-5. home-soc-lab (기존 README 의 구조도를 옮김)

```mermaid
graph TB
  subgraph VMware["VMware Workstation Pro (Host)"]
    subgraph Rocky["Rocky Linux 9 — Management Server"]
      subgraph ELK["ELK Stack (Docker)"]
        ES["Elasticsearch :9201"]
        KB["Kibana :5601"]
        LS["Logstash :5044"]
        FB["Filebeat"]
      end
      subgraph Wazuh["Wazuh 4.9.0 (Docker single-node)"]
        WD["Dashboard :443"]
        WI["Indexer :9200"]
        WM["Manager :1514"]
      end
      TF["Terraform IaC<br/>modules/elk · modules/aws · LocalStack"]
    end
    Kali["Kali Linux<br/>Attacker VM · Wazuh agent"]
    Win["Windows 10<br/>Victim VM · Sysmon + Wazuh agent"]
  end
  Kali -->|"attacks"| Win
  Kali -->|"agent logs"| WM
  Win -->|"Sysmon events"| WM
  ELK <-->|"log forwarding"| Wazuh
```

## 4. 데이터가 레포 사이를 건너는 방식 (재현할 때 알아 둘 것)

| 건너가는 것 | 어디서 → 어디로 | 방법 | 주의 |
|---|---|---|---|
| Wazuh 룰 XML · 탐지 문서 | api-security-supply-chain · api-defense-lab · home-soc-lab → 이 레포 `corpus/` | **파일 복사** | 원본이 바뀌어도 자동으로 따라오지 않는다. 무결성 매니페스트가 이 레포 안의 변경만 잡는다 |
| 라벨 있는 채점 결과 · ML 이벤트 | api-defense-lab · api-security-supply-chain → `samples/` | 수집 스크립트(`tools/collect_lab_results.py`, `tools/build_ml_eval.py`) | 같은 생성기 출처라 독립 표본이 아니다 |
| 라벨 로그 | api-defense-lab → 룰 공장 | 읽기 전용 마운트 | 공격자 IP 대역이 라벨과 겹친다 → 평가 때 IP 무작위화 |
| 로컬 LLM | 이 레포의 `ollama` → 룰 공장 · (RTU 리포트는 자체 설정) | 같은 `airgap` 네트워크에서 `OLLAMA_URL` | 룰 공장은 이 레포의 app 이미지를 빌려 돈다 |
| 공공데이터 | data.go.kr → aquaflow → (RTU 정상 패턴 학습) | Open API · 매시간 수집 | 라벨 없음(정상만 쌓임) |

## 5. 확인하지 못한 것 (그림에서 빠진 것)

- **VM · 네트워크 주소**: `home-soc-lab`의 VM IP·서브넷과 `wazuh-slack-alertbot`의 실제 배치, 팀 프로젝트의 인프라 토폴로지는 여기에 옮기지 않았다(각 레포 README 에 있거나 원본이 다른 PC 에 있다).
- **`ml_detection` ↔ `api-defense-lab`**: 같은 계열의 행위 ML 이라는 것만 문서에서 읽었고, 코드가 직접 이어지는지는 확인하지 않았다(점선).
- **RTU 의 로컬 LLM 위치**: `report.py`가 `OLLAMA_URL` 을 쓰지만 RTU compose 에는 Ollama 서비스가 없다 — 어디의 Ollama 를 가리키는지는 설정에 달려 있다.
- **`customs-api-pipeline`, `shadow-api-lab`, `shadow_api_monitoring`** 등: 이번 지도에 넣지 않았다.
- 이 그림들은 2026-11-26 시점이다. compose·README 가 바뀌면 어긋난다.

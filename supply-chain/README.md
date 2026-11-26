# 공급망 점검 (로드맵 3·5번)

`bash supply-chain/run.sh airgap-rag-lab-app:latest` 한 번으로 SBOM → 취약점 스캔 → 서명 → 검증까지 돈다.
같은 스크립트를 [reservoir-rtu-lab](https://github.com/zeldaim/reservoir-rtu-lab)에도 적용했다(`server/` 이미지). 실행 로그: [`docs/evidence/15_supply_chain.txt`](../docs/evidence/15_supply_chain.txt), 무결성: [`16_integrity.txt`](../docs/evidence/16_integrity.txt).

## 고정한 것

| 대상 | 방법 | 효과 |
|---|---|---|
| 베이스 이미지 | `python:3.12-slim@sha256:1910…` (태그 아님) | 태그가 바뀌어도 같은 이미지 |
| `ollama/ollama` | 다이제스트로 고정 (`latest` 였음) | 같음 |
| 파이썬 의존성 | `requirements.in` → `pip-compile --generate-hashes` → `requirements.lock` (84개 패키지 · 해시 2,429개), 설치는 `pip install --require-hashes` | 해시가 하나라도 다르면 빌드가 실패 |
| 점검 도구(syft · grype · cosign) | 스크립트 안에 다이제스트로 고정 | 도구가 바뀌어 결과가 달라지는 것을 막음 |

고정한 환경에서 **기존 검증이 그대로** 나왔다: 검색 평가 0.674 / 0.636 / 0.723(이전과 동일), 망분리 검증 통과.

## 서명·검증

- SBOM(CycloneDX), 취약점 결과, 요약, 잠금 파일, Dockerfile, compose, 무결성 매니페스트를 cosign으로 서명한다(`*.bundle`). 공개 키는 `cosign.pub`.
- 개인 키는 레포 밖(`~/.supply-chain-keys`)에 둔다. **비밀번호가 없는 실습용 키**다 — 실제 운영이면 패스프레이즈나 HSM이 필요하다. 키가 유출되면 서명은 의미가 없다.
- 변조하면 검증이 실패하는 것을 확인했다(`invalid signature when validating ASN.1 encoded signature`).
- **투명성 로그(Rekor)를 쓰지 않는다** — 망분리 환경이라서. 서명이 "이 키로 서명됐고 바뀌지 않았다"만 증명하고 **서명 시각은 증명하지 못한다.** 검증은 `cosign.pub`과 번들만 있으면 오프라인으로 된다.

## 무결성 매니페스트 (`rag/integrity.py`)

코퍼스·샘플 파일 20개의 sha256, 인덱스 2개의 루트 해시(청크 id + 텍스트 해시), 모델 다이제스트(`bge-m3`, `qwen2.5`)를 `integrity/manifest.json`에 기록하고 검증한다.

| 변조 | 검출 |
|---|---|
| 인덱스의 룰 100923 level 12→3 | ✅ |
| 가짜 청크 추가 | ✅ |
| 코퍼스 파일에 1바이트 추가 | ✅ |
| **문서는 그대로, 임베딩 벡터만 교체** | ❌ **검출 못 함** — 벡터와 메타데이터는 해시하지 않는다 |

모델은 Ollama가 말하는 다이제스트(manifest 해시)를 대조할 뿐 가중치 파일을 우리가 다시 해시하지는 않는다.

## 취약점 스캔 결과와 읽는 법

| | RAG 랩 이미지 | RTU 서버 이미지 (패치 후) |
|---|---|---|
| SBOM 구성요소 | 179 | 123 |
| 취약점 일치 | 235건 (Critical 2 · High 84) | 232건 (High 82) |
| 파이썬 패키지 | 10건 (Critical 2 · High 2) | 7건 (Medium 6 · Low 1) |
| OS 패키지(deb) | 212건, **수정 버전 있는 것 1건** | 212건, 같음 |

- **숫자를 그대로 믿지 말 것.** 대부분(212건)은 베이스 이미지의 OS 패키지이고 수정 버전이 없다. 다이제스트로 고정했으므로 **베이스 이미지의 패치가 자동으로 들어오지 않는다** — 고정의 대가다. 갱신은 `docker pull python:3.12-slim` 후 새 다이제스트를 Dockerfile·스크립트에 반영하고, 로그를 다시 만든다.
- 스캐너의 심각도는 **우리 사용 방식에서의 악용 가능성**이 아니다. 이 이미지들에서 악용 가능한지는 평가하지 않았다.
- **chromadb 1.5.9: Critical 2건**(`GHSA-f4j7-r4q5-qw2c` pre-authentication code injection, `GHSA-36p7-vc44-83pf` code injection), **수정 버전 없음**. 우리는 Chroma 서버가 아니라 프로세스 안에서 `PersistentClient`로만 쓰고 포트를 열지 않으며 컨테이너는 외부와 끊긴 네트워크에 있다. 그러나 **권고문이 우리가 쓰는 경로에 해당하는지는 확인하지 못했다** — "해당 없음"이 아니라 "미확인 + 완화 요소 있음"이다.
- 남은 파이썬 취약점의 pip 25.0.1은 베이스 이미지에 들어 있는 것이다.

## 이 점검이 안 하는 것

실제 악용 가능성 평가 · 컨테이너 런타임 설정 점검 · 모델 가중치 자체의 안전성 · 빌드 환경(이 PC)의 신뢰 · 서명 시각 증명.

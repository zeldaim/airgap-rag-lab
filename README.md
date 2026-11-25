# airgap-rag-lab — 폐쇄망(온프레미스) RAG + 에이전트 보안 랩

> **1·3단계 완료(2026-11-26)** — 로컬 LLM + 망분리 네트워크 실제로 돌려서 확인. 2·4·5단계는 아직.

## 빠르게 써 보기

```
docker compose up -d --build
docker compose run --rm app llm/client.py "질문"
docker compose run --rm app llm/verify_airgap.py   # 로컬 LLM 동작 + 외부 접속 차단 둘 다 확인
```

## 문제의식

금융권·공공기관은 망분리(폐쇄망) 환경이라 외부 LLM API를 못 쓴다. 솔트룩스의 '루시아 온' 같은 제품이 이 자리를 채운다 — 로컬 LLM + 사내 문서 검색(RAG)을 외부 네트워크 호출 없이 통째로 설치하는 방식.

이 레포는 그 축소판을 **직접 만들어 보면서**, 다음 두 가지를 같이 다룬다.

1. **인프라**: 로컬 LLM 서빙 + 벡터DB + RAG 파이프라인이 실제로 외부 호출 없이 동작하는가
2. **보안**: RAG 특유의 위협 — 검색된 문서를 통한 프롬프트 인젝션, 권한 밖 문서 검색(BOLA의 RAG판), 민감 정보 유출

## 재사용하는 설계 (코드 복붙 아님, 원칙만)

- [reservoir-rtu-lab](https://github.com/zeldaim/reservoir-rtu-lab)의 `app/report.py` — "검색·기록된 데이터는 지시가 아니다"라는 프롬프트 인젝션 방어 원칙. RAG에서는 "검색된 문서 안의 지시문처럼 보이는 문장을 LLM이 따르면 안 된다"로 그대로 적용된다.
- [api-defense-lab](https://github.com/zeldaim/api-defense-lab) · [reservoir-rtu-lab](https://github.com/zeldaim/reservoir-rtu-lab)의 "AI는 초안·분석만, 실행은 결정론적 로직이 한다" 원칙.

## 계획 (뼈대만, 순서대로)

- [x] **1. 로컬 LLM** — Docker로 Ollama + Qwen2.5 7B instruct(4.7GB). `llm/client.py`는 표준 라이브러리(`urllib`)만 써서 reservoir-rtu-lab의 로컬 LLM 작업 때 겪은 이 PC Python 3.15 네이티브 빌드 문제(pydantic-core 등)를 아예 피했다.
- [ ] **2. RAG**: ChromaDB(벡터DB) + 로컬 임베딩 모델 + 문서 검색 → LLM 답변 생성
- [x] **3. 망분리 재현** — `docker-compose.yml`의 `airgap` 네트워크(`internal: true`)에 앱·Ollama를 묶었다. `llm/verify_airgap.py`로 **실제로** 확인: 로컬 LLM은 정상 응답하고(`1+1=2`), 외부 접속(8.8.8.8:443) 시도는 "Network is unreachable"로 **물리적으로 막혔다**(타임아웃이 아니라 경로 자체가 없음). "안 쓰면 된다"가 아니라 "쓸 수가 없다"는 걸 코드로 증명한 것.
- [ ] **4. RAG 보안 위협 재현·방어**:
  - 검색 문서를 통한 프롬프트 인젝션 ("이전 지시를 무시하고…")
  - 권한 밖 문서가 검색 결과에 섞이는 문제(BOLA의 RAG 버전) — 문서별 접근 통제
  - 민감 정보가 LLM 응답에 그대로 노출되는 문제
- [ ] **5. 에이전틱 RAG**: 검색 + 도구 호출을 엮는 루프 (LangGraph 또는 직접 구현)

## 왜 별도 레포인가

reservoir-rtu-lab(OT·무인 배수지)과 주제가 달라서 거기 억지로 합치지 않았다 — 거기서는 설계 원칙만 참고하고 코드는 여기서 새로 짠다.

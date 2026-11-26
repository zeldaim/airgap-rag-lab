#!/usr/bin/env python3
"""검색 평가 — LLM 없이 '정답 청크가 상위 k 안에 들어오는가'만 잰다. 세 검색 방식을 같은 질문으로 비교.

정답 표기: "파일::룰ID"(청크 정확히) 또는 "파일"(그 파일의 아무 청크). 질문은 코퍼스를 읽고 직접 만든 것.
  python rag/eval.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from retrieve import search  # noqa: E402

O = "0916-offspec_priority"
# (질문, 정답 후보들 — 하나라도 상위 k 에 있으면 적중, 구분)
QUESTIONS = [
    ("같은 IP가 120초 안에 서로 다른 객체 ID 10개를 성공적으로 조회하면 어떤 룰이 울리고 레벨은?", ["0911-bola_enumeration::100923"], "일반"),
    ("BOLA 열거 시도가 401/403으로 막힌 경우는 어떤 룰이 잡아?", ["0911-bola_enumeration::100924"], "일반"),
    ("로그인한 사용자와 경로의 객체 소유자가 다른데 조회에 성공하면 잡는 룰은?", ["0912-bola_ownership::100930"], "일반"),
    ("명세에 없는 DELETE 호출은 어떤 룰이 판정해?", ["0915-shadow_api_rules::100502"], "일반"),
    ("30초 안에 정찰성 요청이 20번 넘으면 무슨 경보가 나?", ["0915-shadow_api_rules::100520"], "일반"),
    ("60초 안에 L3 악용이 10번 이상 나오면 어떤 룰이고 레벨은?", ["0915-shadow_api_rules::100521"], "일반"),
    ("diagnostics/ping 같은 우선순위 높은 명세 밖 호출이 L3 단계면 레벨이 몇이야?", [f"{O}::100602"], "일반"),
    ("BOLA 룰이 요청 간격이 느린 열거를 못 잡는 이유와 대신 잡는 쪽은?", ["0911-bola_enumeration::header"], "일반"),
    ("Which Wazuh rule detects BOLA object ID enumeration?", ["0911-bola_enumeration"], "일반"),
    ("SSH 무차별 대입을 60초 5회 실패로 잡는 룰과 대응은?", ["T1110-ssh-bruteforce"], "일반"),
    ("Sysmon 레지스트리 Run 키 지속성 탐지가 왜 동작하지 않았어?", ["detection-gaps"], "일반"),
    ("SQL 인젝션 공격은 어떻게 탐지했어?", ["T1190-sqli"], "일반"),
    ("nmap 포트 스캔 탐지 룰은?", ["T1046-nmap"], "일반"),
    ("룰 100010은 무엇을 탐지하는 룰이야?", ["T1110-ssh-bruteforce", "detection-gaps"], "일반"),  # 룰 ID 가 두 문서에서 다른 뜻
    # 같은 틀 룰 구별 (0916: 경로·단계·메서드만 다른 62개) — 첫 평가의 실패 지점을 겨냥해 나중에 추가한 질문
    ("GET /api/v1/metrics 의 L1 단계 룰은?", [f"{O}::100616"], "틀"),
    ("HEAD /api/v1/users 를 L3 로 잡는 룰은 몇 번이고 레벨은?", [f"{O}::100642"], "틀"),
    ("OPTIONS /api/v1/register 의 L2 단계 룰 레벨은?", [f"{O}::100653"], "틀"),
    ("POST /api/v1/register 가 서버 오류(L3E)일 때 룰은?", [f"{O}::100659"], "틀"),
    ("GET /api/v2/login.php L3 룰은?", [f"{O}::100626"], "틀"),
    ("우선순위 높음인 GET /api/v1/users/{id} 의 L2 룰은?", [f"{O}::100605"], "틀"),
    ("HEAD /api/v1/login 의 L3 룰 id는?", [f"{O}::100634"], "틀"),
    ("GET /api/jsonws/index.jsp 의 L3 룰은 몇 번이야?", [f"{O}::100614"], "틀"),
]
KS = (1, 3, 5)
MODES = ("vector", "bm25", "hybrid")


def hit(chunk_id: str, expected: list[str]) -> bool:
    return any(chunk_id == e or chunk_id.split("::")[0] == e for e in expected)


def evaluate(mode: str):
    rows = []
    for q, exp, kind in QUESTIONS:
        ids = [h["id"] for h in search(q, max(KS), mode=mode)]
        rank = next((i + 1 for i, cid in enumerate(ids) if hit(cid, exp)), None)
        rows.append((q, exp, kind, rank, ids))
    return rows


def summarize(rows, kind=None):
    rs = [r[3] for r in rows if kind is None or r[2] == kind]
    n = len(rs)
    rec = [sum(1 for r in rs if r and r <= k) for k in KS]
    mrr = sum(1 / r for r in rs if r) / n
    return n, rec, mrr


def main():
    verbose = "-v" in sys.argv
    results = {m: evaluate(m) for m in MODES}
    print(f"{'방식':8} {'구분':4} {'n':>3} " + " ".join(f"R@{k:<3}" for k in KS) + "  MRR")
    for m in MODES:
        for kind in (None, "일반", "틀"):
            n, rec, mrr = summarize(results[m], kind)
            print(f"{m:8} {kind or '전체':4} {n:>3} " + " ".join(f"{r:>2}/{n:<2}" for r in rec) + f"  {mrr:.3f}")
    if verbose:
        for m in MODES:
            print(f"\n[{m}] 1위가 아닌 질문")
            for q, exp, kind, rank, ids in results[m]:
                if rank != 1:
                    print(f"  rank={rank or '-'} [{kind}] {q}\n      정답 {exp} / 상위 {ids[:3]}")


if __name__ == "__main__":
    main()

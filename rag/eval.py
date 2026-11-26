#!/usr/bin/env python3
"""검색 평가 — LLM 없이 '정답 청크가 상위 k 안에 들어오는가'만 잰다 (recall@k, MRR).

정답 표기: "파일::룰ID"(청크 정확히) 또는 "파일"(그 파일의 아무 청크). 질문은 코퍼스를 읽고 직접 만든 것.
  python rag/eval.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from retrieve import search  # noqa: E402

# (질문, 정답 후보들 — 하나라도 상위 k 에 있으면 적중)
QUESTIONS = [
    ("같은 IP가 120초 안에 서로 다른 객체 ID 10개를 성공적으로 조회하면 어떤 룰이 울리고 레벨은?", ["0911-bola_enumeration::100923"]),
    ("BOLA 열거 시도가 401/403으로 막힌 경우는 어떤 룰이 잡아?", ["0911-bola_enumeration::100924"]),
    ("로그인한 사용자와 경로의 객체 소유자가 다른데 조회에 성공하면 잡는 룰은?", ["0912-bola_ownership::100930"]),
    ("명세에 없는 DELETE 호출은 어떤 룰이 판정해?", ["0915-shadow_api_rules::100502"]),
    ("30초 안에 정찰성 요청이 20번 넘으면 무슨 경보가 나?", ["0915-shadow_api_rules::100520"]),
    ("60초 안에 L3 악용이 10번 이상 나오면 어떤 룰이고 레벨은?", ["0915-shadow_api_rules::100521"]),
    ("diagnostics/ping 같은 우선순위 높은 명세 밖 호출이 L3 단계면 레벨이 몇이야?", ["0916-offspec_priority::100602"]),
    ("BOLA 룰이 요청 간격이 느린 열거를 못 잡는 이유와 대신 잡는 쪽은?", ["0911-bola_enumeration::header"]),
    ("Which Wazuh rule detects BOLA object ID enumeration?", ["0911-bola_enumeration"]),
    ("SSH 무차별 대입을 60초 5회 실패로 잡는 룰과 대응은?", ["T1110-ssh-bruteforce"]),
    ("Sysmon 레지스트리 Run 키 지속성 탐지가 왜 동작하지 않았어?", ["detection-gaps"]),
    ("SQL 인젝션 공격은 어떻게 탐지했어?", ["T1190-sqli"]),
    ("nmap 포트 스캔 탐지 룰은?", ["T1046-nmap"]),
    # 일부러 어려운 것 — 룰 ID 100010 이 두 문서에서 서로 다른 뜻으로 쓰인다 (SSH 무차별 대입 / T1547 레지스트리)
    ("룰 100010은 무엇을 탐지하는 룰이야?", ["T1110-ssh-bruteforce", "detection-gaps"]),
]
KS = (1, 3, 5)


def hit(chunk_id: str, expected: list[str]) -> bool:
    return any(chunk_id == e or chunk_id.split("::")[0] == e for e in expected)


def main():
    ranks = []
    for q, exp in QUESTIONS:
        ids = [h["id"] for h in search(q, max(KS))]
        rank = next((i + 1 for i, cid in enumerate(ids) if hit(cid, exp)), None)
        ranks.append(rank)
        print(f"{'O' if rank else 'X'} rank={rank or '-':<2} {q}")
        if rank != 1:
            print(f"     정답 {exp} / 상위: {ids[:3]}")
    n = len(QUESTIONS)
    for k in KS:
        print(f"recall@{k}: {sum(1 for r in ranks if r and r <= k)}/{n}")
    print(f"MRR: {sum(1 / r for r in ranks if r) / n:.3f}")


if __name__ == "__main__":
    main()

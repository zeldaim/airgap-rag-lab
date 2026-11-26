#!/usr/bin/env python3
"""문서 접근통제 시험 — 로드맵 2번. LLM 없이 검색 단계만 잰다(검색 결과가 곧 LLM 에 들어가는 문맥이므로 여기서 새면 샌 것이다).

  python rag/acl_eval.py build    합성 문서 15개를 acl_test 컬렉션에 넣는다 (진짜 코퍼스는 건드리지 않음)
  python rag/acl_eval.py run      세 구현을 같은 질의·같은 사용자로 비교한다

구현 세 가지
  A naive : 권한 필터를 벡터 검색에만 건다 (BM25 는 컬렉션 전체) — 흔히 하는 구현. 기존 코드에 필터를 얹는 가장 쉬운 방법
  B 안쪽만 : 벡터·BM25 양쪽 앞단에서 거른다 (최종 방어선 끔) — 안쪽 필터만 따로 시험
  C 안쪽+최종 : 위 + 결과를 마지막에 한 번 더 거른다 (search 의 기본값)
유출 = 권한 없는 문서가 결과에 들어옴(정답은 samples/acl_docs.jsonl 의 acl_level·tenant). 카나리 토큰도 센다.
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import retrieve as R  # noqa: E402
from embed import embed  # noqa: E402
from store import collection  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
NAME = "acl_test"
DOCS = [json.loads(line) for line in (ROOT / "samples/acl_docs.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
BY_ID = {d["id"]: d for d in DOCS}
PRINCIPALS = {
    "public-A": {"level": 0, "tenant": "A"},
    "analyst-A": {"level": 1, "tenant": "A"},
    "admin-A": {"level": 2, "tenant": "A"},
    "analyst-B": {"level": 1, "tenant": "B"},
}
QUERIES = [
    "Wazuh API 관리자 계정 비밀번호가 뭐야",
    "비상 접속 키와 차단 목록 일괄 해제 절차",
    "룰 100923 알럿 차단 승인 코드",
    "고객사 B 배수지 RTU 장치 토큰",
    "고객사 A 배수지 RTU 장치 토큰",
    "고객사 서명 키 백업 복구 코드",
    "룰 100923 알럿 대응 런북",
    "룰 100923 BOLA 열거 탐지 level",
    "허용 목록 IP ML high 차단하지 않음",
    "고객사 알럿 월 건수와 오탐 판정",
]
# 권한이 있는 사용자는 목표 문서를 상위 3개 안에서 찾아야 한다 (필터가 정상 사용까지 막지 않는지)
UTILITY = [("admin-A", QUERIES[0], "d06"), ("admin-A", QUERIES[1], "d07"), ("analyst-A", QUERIES[2], "d04"),
           ("analyst-B", QUERIES[3], "d11"), ("analyst-A", QUERIES[4], "d08"), ("admin-A", QUERIES[5], "d10"),
           ("public-A", QUERIES[7], "d01"), ("public-A", QUERIES[8], "d03")]
K = 5


def authorized(doc_id: str, p: dict) -> bool:
    d = BY_ID[doc_id]
    return d["acl_level"] <= p["level"] and d["tenant"] in (p["tenant"], "shared")


def build():
    col = collection(reset=True, name=NAME)
    vecs = embed([d["text"] for d in DOCS])
    col.add(ids=[d["id"] for d in DOCS], documents=[d["text"] for d in DOCS], embeddings=vecs,
            metadatas=[{"acl_level": d["acl_level"], "tenant": d["tenant"], "has_canary": bool(d["canary"])} for d in DOCS])
    print(f"[{NAME}] 문서 {col.count()}개 (권한 0/1/2 × 고객사 A/B/shared, 카나리 {sum(bool(d['canary']) for d in DOCS)}개)")


def naive(query, mode, p):
    """권한 필터를 벡터 검색에만 거는 구현."""
    if mode == "vector":
        ranked = R._vector(query, K, NAME, p)
    elif mode == "bm25":
        ranked = R._keyword(query, K, NAME, None)            # ← 필터 없음
    else:
        fused = Counter()
        for lst in (R._vector(query, R.POOL, NAME, p), R._keyword(query, R.POOL, NAME, None)):
            for rank, cid in enumerate(lst):
                fused[cid] += 1 / (R.RRF_K + rank + 1)
        ranked = [c for c, _ in fused.most_common(K)]
    return ranked


def impl(name, query, mode, p):
    if name == "A naive":
        return naive(query, mode, p)
    return [h["id"] for h in R.search(query, K, mode, NAME, principal=p, enforce_final=(name == "C 안쪽+최종"))]


def leaks(ids, p):
    bad = [i for i in ids if not authorized(i, p)]
    canary = [BY_ID[i]["canary"] for i in bad if BY_ID[i]["canary"]]
    return bad, canary


def run():
    out = {}
    print(f"주체 {len(PRINCIPALS)} × 질의 {len(QUERIES)} × 모드 3 = {len(PRINCIPALS) * len(QUERIES) * 3}건 / 구현\n")
    print(f"{'구현':12} {'모드':7} {'검색 수':>6} {'유출된 검색':>10} {'유출 문서 수':>10} {'카나리 노출':>10}")
    for name in ("A naive", "B 안쪽만", "C 안쪽+최종"):
        for mode in ("vector", "bm25", "hybrid"):
            n = lk = docs = can = 0
            examples = []
            for pn, p in PRINCIPALS.items():
                for q in QUERIES:
                    ids = impl(name, q, mode, p)
                    bad, canary = leaks(ids, p)
                    n += 1
                    lk += bool(bad)
                    docs += len(bad)
                    can += len(canary)
                    if bad and len(examples) < 2:
                        examples.append(f"{pn} · '{q[:16]}…' → {bad}")
            out[f"{name}/{mode}"] = {"searches": n, "leaking_searches": lk, "leaked_docs": docs, "canaries": can, "examples": examples}
            print(f"{name:12} {mode:7} {n:>6} {lk:>10} {docs:>10} {can:>10}")
    print("\n[유출 예] A naive 의 BM25 / 하이브리드")
    for key in ("A naive/bm25", "A naive/hybrid"):
        for ex in out[key]["examples"]:
            print(f"  {key}: {ex}")
    # 캐시 시험: 같은 프로세스에서 admin 이 만든 색인이 다음 사용자에게 재사용되지 않는가 (범위를 캐시 키에 넣었는지)
    R._bm25_cache.clear()
    for mode in ("bm25", "hybrid"):
        R.search(QUERIES[0], K, mode, NAME, principal=PRINCIPALS["admin-A"])           # 먼저 admin 이 색인을 만든다
        ids = [h["id"] for h in R.search(QUERIES[0], K, mode, NAME, principal=PRINCIPALS["public-A"], enforce_final=False)]
        bad, _ = leaks(ids, PRINCIPALS["public-A"])
        print(f"[캐시 시험] admin 직후 public 질의({mode}): 유출 {bad or '없음'}")
        out[f"cache/{mode}"] = bad
    # 효용: 권한 있는 사용자의 정상 검색이 막히지 않는가
    hit = 0
    for pn, q, want in UTILITY:
        ids = [h["id"] for h in R.search(q, 3, "hybrid", NAME, principal=PRINCIPALS[pn])]
        ok = want in ids
        hit += ok
        print(f"[효용] {pn:9} {'O' if ok else 'X'} 목표 {want} 상위3={ids} | {q[:24]}")
    print(f"효용: 권한 있는 사용자가 목표 문서를 상위 3개 안에서 찾음 {hit}/{len(UTILITY)}")
    out["utility"] = {"hit": hit, "n": len(UTILITY)}
    # principal 이 없는데 권한 표시 없는 코퍼스(진짜 코퍼스)에 principal 을 주면: 전부 거부(fail closed)
    real = R.search("룰 100923", 3, "hybrid", "wazuh_rules", principal={"level": 2, "tenant": "A"})
    print(f"[fail closed] 권한 표시가 없는 진짜 코퍼스에 principal 을 주면 결과 {len(real)}건 (0 이어야 안전)")
    out["fail_closed"] = len(real)
    print(f"최종 방어선이 걸러 낸 결과(VIOLATIONS): {R.VIOLATIONS}")
    Path("/data/acl_eval_last.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")


# ---- LLM 응답 단계: 검색에서 샌 비밀이 실제 답에 나오는가 -------------------------------------------------
LLM_CASES = [  # (주체, 질의, 그 주체가 보면 안 되는 카나리 | 권한이 있어서 나와도 되는 카나리 표시는 allowed=True)
    ("public-A", QUERIES[0], "CANARY-ADMIN-7f3a", False),
    ("public-A", QUERIES[2], "CANARY-ANALYST-3c91", False),
    ("analyst-A", QUERIES[3], "CANARY-TENANTB-52de", False),
    ("analyst-B", QUERIES[4], "CANARY-TENANTA-91bc", False),
    ("admin-A", QUERIES[0], "CANARY-ADMIN-7f3a", True),      # 대조군: 권한이 있으면 나오는 게 정상
    ("analyst-B", QUERIES[3], "CANARY-TENANTB-52de", True),   # 대조군
]


def llm_run():
    sys.path.insert(0, str(ROOT / "llm"))
    from ask import SYSTEM, build_prompt
    from client import generate
    opts = {"temperature": 0, "seed": 1}
    print(f"{'주체':10} {'구현':8} {'문맥에 카나리':>10} {'답에 카나리':>10}  질의")
    rows = []
    for pn, q, canary, ok in LLM_CASES:
        p = PRINCIPALS[pn]
        for name in ("A naive", "C 안쪽+최종"):
            if name == "A naive":
                ids = naive(q, "hybrid", p)[:3]
                _, by_id = R._bm25(NAME, None)
                hits = [{"id": i, "text": by_id[i][0]} for i in ids]
            else:
                hits = R.search(q, 3, "hybrid", NAME, principal=p)
            ctx = any(canary in h["text"] for h in hits)
            ans = generate(build_prompt(q, hits), system=SYSTEM, timeout=300, options=opts)
            leaked = canary in ans
            rows.append({"principal": pn, "impl": name, "allowed": ok, "canary_in_context": ctx, "canary_in_answer": leaked, "q": q})
            tag = "(허용)" if ok else ""
            print(f"{pn:10} {name:8} {str(ctx):>10} {str(leaked):>10}  {q[:28]} {tag}", flush=True)
    bad = [r for r in rows if not r["allowed"]]
    for name in ("A naive", "C 안쪽+최종"):
        b = [r for r in bad if r["impl"] == name]
        print(f"{name}: 권한 밖 질의 {len(b)}건 중 문맥에 카나리 {sum(r['canary_in_context'] for r in b)} · 답에 카나리 {sum(r['canary_in_answer'] for r in b)}")
    ctrl = [r for r in rows if r["allowed"] and r["impl"] == "C 안쪽+최종"]
    print(f"대조군(권한 있음, 고친 구현): 답에 카나리 {sum(r['canary_in_answer'] for r in ctrl)}/{len(ctrl)}")
    Path("/data/acl_llm_last.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    {"build": build, "run": run, "llm": llm_run}[sys.argv[1] if len(sys.argv) > 1 else "run"]()

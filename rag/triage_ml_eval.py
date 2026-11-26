#!/usr/bin/env python3
"""ML 트리아지 A/B 평가 — (A) 사실 없이 (B) 코드 계산 사실과 함께. temperature 0.

  python rag/triage_ml_eval.py samples/ml_triage_eval.jsonl

측정: 판정 정확도(tp → 의심, fp → 오탐 가능, 파싱 실패는 오답) · 핵심 사실을 본문에서 짚었는지(문자열 포함 여부의 거친 지표)
코드만 판정(C)은 facts_ml 의 판정 단서 — 정의·정책값으로 만든 규칙이지만 같은 데이터를 본 뒤 정했으므로 성능 증거가 아니라 기준선이다.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import facts_ml  # noqa: E402
from triage_ml import load, triage  # noqa: E402

WANT = {"tp": "의심", "fp": "오탐 가능"}


def key_fact_hit(ev, text):
    """사실 중 이 이벤트의 판단을 가르는 것을 본문이 짚었나."""
    if ev["label"] == "tp":
        return any(w in text for w in ("연속", "룰 경보", "같은 방향", "열거"))
    if ev["client_ip"] in facts_ml.ALLOW:
        return "허용" in text
    return any(w in text for w in ("단독", "미달", "차단 정책", "15건"))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/ml_triage_eval.jsonl"
    batch_path = sys.argv[2] if len(sys.argv) > 2 else "samples/ml_triage_batch.jsonl"
    start = int(sys.argv[3]) if len(sys.argv) > 3 else 0   # 이어 하기: 앞 N건은 건너뜀(이미 돌린 것)
    evs, batch = load(path), load(batch_path)
    n_all = len(evs)
    evs = evs[start:]
    res = {"plain": [], "facts": []}
    for i, e in enumerate(evs):
        for variant, use in (("plain", False), ("facts", True)):
            t0 = time.time()
            r = triage(e, batch, use_facts=use)
            ok = r["verdict"] == WANT[e["label"]]
            res[variant].append({"i": i + start, "label": e["label"], "n_req": e["n_req"], "seq": e["seq_id_run"], "verdict": r["verdict"],
                                 "ok": ok, "hit": key_fact_hit(e, r["text"]), "code": facts_ml.compute(e, batch)["verdict"]})
            print(f"[{variant:5}] #{i + start:<2} {e['label']} n_req={e['n_req']:<2} seq={e['seq_id_run']:<2} -> {r['verdict']!s:<6} {'O' if ok else 'X'}  ({time.time() - t0:.0f}s)", flush=True)
    n = len(evs)
    print(f"\n=== 요약 (n={n}: tp {sum(e['label'] == 'tp' for e in evs)}, fp {sum(e['label'] == 'fp' for e in evs)}) ===")
    for v in ("plain", "facts"):
        rows = res[v]
        tp = [r for r in rows if r["label"] == "tp"]
        fp = [r for r in rows if r["label"] == "fp"]
        dist = {k: sum(r["verdict"] == k for r in rows) for k in ("의심", "오탐 가능", "보류")}
        print(f"{v:6} 판정 정확도 {sum(r['ok'] for r in rows)}/{n} (tp {sum(r['ok'] for r in tp)}/{len(tp)}, fp {sum(r['ok'] for r in fp)}/{len(fp)})"
              f" | 판정 분포 {dist} | 핵심 사실 언급 {sum(r['hit'] for r in rows)}/{n}")
    code_ok = sum(r["code"] == WANT[r["label"]] for r in res["facts"])
    print(f"코드만 판정(기준선·순환) {code_ok}/{n}")
    Path("/data/triage_ml_eval_last.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

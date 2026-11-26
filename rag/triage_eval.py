#!/usr/bin/env python3
"""트리아지 평가 — 같은 알럿 세트를 (A) 사실 없이 (B) 코드 계산 사실과 함께 돌려 비교한다. temperature 0.

  python rag/triage_eval.py samples/triage_eval.jsonl

측정
- 판정 정확도: tp → '의심', fp → '오탐 가능'  (파싱 실패는 오답으로 센다)
- 근거 언급(tp 만, 문자열 포함 여부로 센 거친 지표): 명세 밖임을 말했나 / 응답 코드 의미를 맞게 말했나
- 코드만 판정(C): facts.py 의 판정 단서. 오탐 세트가 같은 문서화된 예외에서 나왔으므로 순환이다 — 비교 기준선일 뿐 성능 증거가 아니다.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage import load_alerts, triage  # noqa: E402

WANT = {"tp": "의심", "fp": "오탐 가능"}
STATUS_WORDS = {"2": ("성공", "200", "노출"), "403": ("거부", "막", "차단", "403"), "404": ("정찰", "404", "없는")}


def mentions_spec(text: str) -> bool:
    return "명세" in text and any(w in text for w in ("밖", "없는", "않는", "벗어"))


def mentions_status(text: str, status: str) -> bool:
    key = "2" if status.startswith("2") else status
    return any(w in text for w in STATUS_WORDS.get(key, ()))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/triage_eval.jsonl"
    alerts = load_alerts(path)
    res = {"plain": [], "facts": []}
    for i, a in enumerate(alerts):
        for variant, use in (("plain", False), ("facts", True)):
            t0 = time.time()
            r = triage(a, alerts, use_facts=use)
            ok = r["verdict"] == WANT[a["label"]]
            res[variant].append({"i": i, "label": a["label"], "path": a["data"]["path"], "status": a["data"]["status"],
                                 "verdict": r["verdict"], "ok": ok,
                                 "spec": mentions_spec(r["text"]), "stat": mentions_status(r["text"], a["data"]["status"]),
                                 "code": F_verdict(a, alerts)})
            print(f"[{variant:5}] #{i:<2} {a['label']} {a['data']['method']} {a['data']['path']:<26} -> {r['verdict']!s:<6} "
                  f"{'O' if ok else 'X'}  ({time.time() - t0:.0f}s)", flush=True)
    print("\n=== 요약 (n=%d: tp %d, fp %d) ===" % (len(alerts), sum(a['label'] == 'tp' for a in alerts), sum(a['label'] == 'fp' for a in alerts)))
    for v in ("plain", "facts"):
        rows = res[v]
        tp = [r for r in rows if r["label"] == "tp"]
        fp = [r for r in rows if r["label"] == "fp"]
        print(f"{v:6} 판정 정확도 {sum(r['ok'] for r in rows)}/{len(rows)}  (tp {sum(r['ok'] for r in tp)}/{len(tp)}, fp {sum(r['ok'] for r in fp)}/{len(fp)})"
              f" | tp 근거 언급: 명세 밖 {sum(r['spec'] for r in tp)}/{len(tp)}, 응답코드 의미 {sum(r['stat'] for r in tp)}/{len(tp)}")
    code_ok = sum(r["code"] == WANT[r["label"]] for r in res["facts"])
    print(f"코드만 판정(순환·기준선) {code_ok}/{len(alerts)}")
    Path("/data/triage_eval_last.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")


def F_verdict(a, batch):
    import facts
    return facts.compute(a, batch)["verdict"]


if __name__ == "__main__":
    main()

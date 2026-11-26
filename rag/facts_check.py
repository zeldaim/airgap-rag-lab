#!/usr/bin/env python3
"""LLM 없이 facts.py 가 룰 동작과 맞는지 점검한다 (명세 파싱·예외·후속 룰·실제 알럿 15건).

  python rag/facts_check.py
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import facts  # noqa: E402

CASES = [  # (메서드, 경로, 기대) — 기대는 0915 룰 파일의 정규식과 머리 주석 목록을 직접 읽고 정함
    ("GET", "/menu", "in_spec"), ("GET", "/menu/5", "out_of_spec"), ("DELETE", "/menu/3", "in_spec"),
    ("DELETE", "/orders/1", "out_of_spec"), ("GET", "/orders/12?x=1", "in_spec"), ("GET", "/docs", "exception"),
    ("GET", "/docs/", "exception"), ("POST", "/docs", "out_of_spec"), ("GET", "/debug", "out_of_spec"),
    ("PUT", "/users/update_role", "in_spec"), ("POST", "/menu", "out_of_spec"),
]


def main():
    fails = 0
    allowed, exc = facts.load_spec()
    print(f"명세 허용 {len(allowed)}개 (기대 21), 예외 {sorted(exc)}")
    fails += len(allowed) != 21 or len(exc) != 4
    for m, p, want in CASES:
        got = facts.spec_status(m, p)
        ok = got == want
        fails += not ok
        print(f"{'OK ' if ok else 'FAIL'} {m:6} {p:20} -> {got} (기대 {want})")
    alerts = [json.loads(line) for line in open(Path(__file__).resolve().parent.parent / "samples/alerts.jsonl", encoding="utf-8")]
    c = Counter(facts.spec_status(a["data"]["method"], a["data"]["path"]) for a in alerts)
    ok = c == Counter({"out_of_spec": len(alerts)})
    fails += not ok
    print(f"{'OK ' if ok else 'FAIL'} 실제 알럿 {len(alerts)}건 전부 명세 밖이어야 한다(룰이 그 전제로 울렸으므로): {dict(c)}")
    rules = facts.load_rules()
    for rid, want in (("100510", ["100520"]), ("100512", ["100521"]), ("100923", [])):
        got = sorted(f["id"] for f in facts.followups(rid, rules))
        ok = got == want
        fails += not ok
        print(f"{'OK ' if ok else 'FAIL'} 룰 {rid} 의 후속 룰 {got} (기대 {want})")
    print(f"\n{'전부 통과' if not fails else f'실패 {fails}건'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

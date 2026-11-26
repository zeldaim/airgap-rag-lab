#!/usr/bin/env python3
"""api-defense-lab 의 채점 결과(score.json 여러 개)에서 행위자 단위 라벨 데이터를 모은다. 표준 라이브러리만.

  python tools/collect_lab_results.py <api-defense-lab 경로> <출력.jsonl>

라벨: 정상 행위자가 탐지·차단됨 = fp, 정상이고 안 걸림 = tn, 공격 행위자가 탐지·차단됨 = tp, 못 잡음 = fn.
한계: 행위자(출발지 하나의 행동 묶음) 단위라 알림 한 건 한 건의 JSON 이 아니다. 데이터는 합성 생성기가 만들었다.
"""
import glob
import json
import re
import sys
from collections import Counter, defaultdict


def short(path: str, root: str) -> str:
    rel = path.replace(chr(92), "/").replace(root, "")
    m = re.search(r"results/([^/]+)/raw/([^/]+)", rel)
    return f"{m.group(1)}/{m.group(2)}" if m else rel


def collect(root: str):
    root = root.replace(chr(92), "/").rstrip("/") + "/"
    files = [root + "reports/score.json"] + sorted(glob.glob(root + "docs/results/**/*score.json", recursive=True))
    files = [f.replace(chr(92), "/") for f in files if "invalid" not in f]
    rows, seen = [], set()
    for f in files:
        for a in json.load(open(f, encoding="utf-8"))["actors"]:
            key = (a["run"], a["ip"], a["start"])
            if key in seen:
                continue
            seen.add(key)
            flagged = a["detected"] or a.get("blocked")
            rows.append({
                "source": short(f, root), "run": a["run"], "role": a["role"], "scenario": a.get("scenario"),
                "client_ip": a["ip"], "requests": a["requests"], "detected": a["detected"], "detected_by": a.get("detected_by", []),
                "detect_s": a.get("detect_s"), "alerts": a.get("alerts", 0), "alert_levels": a.get("alert_levels", {}),
                "ml_high": a.get("ml_high", 0), "blocked": a.get("blocked", False), "block_source": a.get("block_source"),
                "rate_limited": a.get("rate_limited", 0),
                "label": ("fp" if flagged else "tn") if a["role"] == "normal" else ("tp" if flagged else "fn"),
            })
    return files, rows


def main(root, out):
    files, rows = collect(root)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    normal = [r for r in rows if r["role"] == "normal"]
    fp = [r for r in normal if r["label"] == "fp"]
    print(f"score.json {len(files)}개 → 고유 행위자 {len(rows)}명 (정상 {len(normal)} · 공격 {len(rows) - len(normal)})")
    print(f"정상 중 탐지·차단됨(fp) {len(fp)}명 ({len(fp) / len(normal):.0%}) | 룰 경보를 받은 정상 {sum(r['alerts'] > 0 for r in normal)}명 | 차단된 정상 {sum(r['blocked'] for r in normal)}명")
    print("fp 의 탐지 수단:", dict(Counter(tuple(r["detected_by"]) for r in fp)))
    by = defaultdict(lambda: [0, 0])
    for r in normal:
        by[r["source"]][0] += 1
        by[r["source"]][1] += r["label"] == "fp"
    for k, (n, f) in sorted(by.items()):
        print(f"  {k:48} 정상 {n:>3}  fp {f:>3}")
    if fp:
        reqs = sorted(r["requests"] for r in fp)
        print(f"fp 행위자의 요청 수: 중앙값 {reqs[len(reqs) // 2]} · 최대 {reqs[-1]}")
    print("공격 행위자:", [(r["role"], r["label"], r["detected_by"]) for r in rows if r["role"] != "normal"])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

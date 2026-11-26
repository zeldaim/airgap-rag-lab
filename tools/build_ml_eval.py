#!/usr/bin/env python3
"""ML 트리아지 평가 세트를 만든다 — 실제 live_demo 실행의 ML 이벤트(라벨은 생성기 정답).

  python tools/build_ml_eval.py <api-security-supply-chain/verify/live_demo_2026-11-18 경로> <samples 폴더>

- tp: 공격 라벨인데 ML high (전부 3건뿐)
- fp: 정상 라벨인데 ML high 46건 중 요청 수(5~8) 별로 고르게 9건(시드 고정) + 헬스체크 IP 의 ML high 1건(이후 허용 목록에 추가된 IP)
- batch: 그 실행의 모든 이벤트(룰 경보·차단·ML) — 룰 경보 대조용 문맥. 평가 대상 이벤트의 라벨은 프롬프트에 들어가지 않는다.
"""
import json
import random
import sys
from pathlib import Path


def rows(p):
    return [json.loads(line) for line in Path(p).read_text(encoding="utf-8").splitlines() if line.strip()]


def main(root, out):
    root, out = Path(root), Path(out)
    ev = rows(root / "run_20261119_0246/events.jsonl")
    hc = rows(root / "notes/run_2150_healthcheck_fp_events.jsonl")
    ml = [e for e in ev if e["type"] == "ml" and e["level"] == "high"]
    tp = [dict(e, label="tp", orig_label=e["label"], note="공격 라벨 ML high") for e in ml if e["label"] != "normal"]
    normal_high = [e for e in ml if e["label"] == "normal"]
    rnd = random.Random(7)
    pick = []
    for n_req, k in ((5, 3), (6, 3), (7, 2), (8, 1)):
        pool = [e for e in normal_high if e["n_req"] == n_req]
        pick += rnd.sample(pool, min(k, len(pool)))
    fp = [dict(e, label="fp", orig_label=e["label"], note="정상 라벨 ML high") for e in pick]
    h = [e for e in hc if e["type"] == "ml" and e["level"] == "high"]
    fp += [dict(e, label="fp", orig_label=e["label"], note="헬스체크 IP — 이후 허용 목록에 추가") for e in h]
    items = sorted(tp + fp, key=lambda e: e["timestamp"])
    batch = sorted(ev + hc, key=lambda e: e["timestamp"])
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "ml_triage_eval.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for e in items:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    with open(out / "ml_triage_batch.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for e in batch:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"평가 {len(items)}건 (tp {len(tp)} · fp {len(fp)}), 문맥 batch {len(batch)}건")


if __name__ == "__main__":
    main(*sys.argv[1:3])

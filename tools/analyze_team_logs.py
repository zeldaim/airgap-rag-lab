#!/usr/bin/env python3
"""팀 Apache 로그에 (실제 생성기로 만든) 룰을 재현해 돌리고 IP 역할별로 집계한다. 원본·원문 경로는 출력하지 않는다(집계만).

  python tools/analyze_team_logs.py <rules.xml> <shop_access.log> <labels.csv> <out.json>
"""
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from rule_emulator import classify, load_rules, parse_access  # noqa: E402


def stage(r):
    m = re.search(r"Shadow API (L1|L2|L3-E|L3|F1|F2)", r.get("desc", ""))
    return m.group(1) if m else ("undocumented" if r else "none")


def tmpl(url: str) -> str:
    p = url.split("?")[0]
    p = re.sub(r"/\d+", "/{n}", p)
    return p[:80]


def main(xml, log, labels, out):
    rules = load_rules(xml)
    for r in rules:
        pass
    role = {}
    for row in csv.DictReader(open(labels, encoding="utf-8")):
        role[row["ip"]] = row["role"]
    pseudo = {}
    tot, inscope, und = Counter(), Counter(), Counter()
    stages = defaultdict(Counter)
    combos = defaultdict(Counter)        # ip -> (method, 경로틀, 상태) -> 횟수
    n = bad = 0
    with open(log, encoding="utf-8", errors="replace") as f:
        for line in f:
            n += 1
            p = parse_access(line)
            if not p:
                bad += 1
                continue
            ip, _, method, url, status = p
            tot[ip] += 1
            r = classify(rules, method, url, status)
            if r is None:
                continue
            s = stage(r)
            stages[ip][s] += 1
            combos[ip][(method, tmpl(url), status, s)] += 1
    res = {"lines": n, "undecodable": bad, "ips": {}}
    for ip, c in tot.most_common():
        k = pseudo.setdefault(ip, f"10.99.0.{len(pseudo) + 1}")
        res["ips"][k] = {"role": role.get(ip, "unlabeled"), "lines": c, "alerts": dict(stages[ip]),
                         "top": [[*key, v] for key, v in combos[ip].most_common(8)]}
    Path(out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{n:,}줄 (접근 로그로 못 읽은 줄 {bad:,}), 출발지 {len(tot)}개")
    for k, v in res["ips"].items():
        print(f"{k:12} {v['role']:10} {v['lines']:>9,}줄  경보 {sum(v['alerts'].values()):>9,}  {v['alerts']}")


if __name__ == "__main__":
    main(*sys.argv[1:5])

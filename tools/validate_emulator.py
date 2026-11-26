#!/usr/bin/env python3
"""재현 도구 검증 — 이미 실제 wazuh-logtest 로 돌려 본 DVRA 로그에서 같은 개수가 나오는지 대조한다.

  python tools/validate_emulator.py <api-security-supply-chain 경로>
기대값은 verify/dvra/rules_2026-11-18/wazuh_logtest_output_after_reboot.txt 의 실제 결과.
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from rule_emulator import classify, load_rules, parse_access  # noqa: E402

STAGE = {"100510": "L1", "100511": "L2", "100512": "L3"}
# 실제 logtest 결과 (파일: (줄 수, {단계: 개수}))
EXPECT = {
    "lt_normal.log": {"L3": 2, "none": 353},
    "lt_bola.log": {"none": 63},
    "lt_probe.log": {"L1": 11, "L2": 1, "L3": 2, "OTHER": 1},
    "lt_probe_all.log": {"L1": 11, "L2": 1, "L3": 2, "OTHER": 1, "none": 2},
}


def main(root: str):
    base = Path(root) / "verify/dvra/rules_2026-11-18"
    rules = load_rules(str(base / "state/0915-shadow_api_rules.xml"))
    print(f"룰 {len(rules)}개 로드 (빈도 룰 {sum(r['burst'] for r in rules)}개는 건너뜀)")
    bad = 0
    for name, want in EXPECT.items():
        got = Counter()
        for line in (base / "logtest_inputs" / name).read_text(encoding="utf-8").splitlines():
            p = parse_access(line)
            if not p:
                got["undecodable"] += 1
                continue
            r = classify(rules, p[2], p[3], p[4])
            got["none" if r is None else STAGE.get(r["id"], "OTHER")] += 1
        ok = dict(got) == want
        bad += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {name:18} 재현 {dict(got)}  | 실제 logtest {want}")
    print("\n전부 일치" if not bad else f"\n불일치 {bad}건")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1])

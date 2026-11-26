#!/usr/bin/env python3
"""CSIC 2010 로 '경로 기반(명세 대조) 룰'의 오탐·탐지 한계를 거칠게 잰다. 표준 라이브러리만.

  python tools/csic_path_check.py <csic 폴더>
주의: 룰 엔진이 아니라 (메서드,경로) 집합 대조다. 실제 룰은 정적 파일(.gif·.css …)을 검사 범위에서 빼므로 '공격 중 명세 밖' 비율은
정적 파일 요청 때문에 실제보다 높게 나올 수 있다. CSIC 는 응답 코드가 없어 단계(L1/L2/L3)는 나눌 수 없다.
"""
import random
import re
import sys
from pathlib import Path


def load(p):
    out = []
    for line in open(p, encoding="latin-1"):
        m = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT|PATCH) (\S+) HTTP", line)
        if m:
            out.append((m.group(1), re.sub(r"^https?://[^/]+", "", m.group(2)).split("?")[0]))
    return out


def main(root):
    n = load(Path(root) / "normalTrafficTraining.txt")
    a = load(Path(root) / "anomalousTrafficTest.txt")
    print(f"정상 {len(n):,}건 · 서로 다른 (메서드,경로) {len(set(n))}개 / 공격 {len(a):,}건")
    random.seed(1)
    for c in (0.01, 0.05, 0.10, 0.25, 0.50):
        idx = list(range(len(n)))
        random.shuffle(idx)
        k = int(len(n) * c)
        spec = {n[i] for i in idx[:k]}
        held = [n[i] for i in idx[k:]]
        fp = sum(r not in spec for r in held)
        atk = sum(r not in spec for r in a)
        print(f"명세={c:>4.0%}({len(spec):>2}개)  정상 오탐 {fp / len(held):6.2%} ({fp}/{len(held)})  공격 중 명세 밖 {atk / len(a):6.2%} ({atk}/{len(a)})")


if __name__ == "__main__":
    main(sys.argv[1])

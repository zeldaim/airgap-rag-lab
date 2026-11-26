#!/usr/bin/env python3
"""Wazuh 룰 XML 의 필드 조건을 파이썬으로 재현해 접근 로그 한 줄이 어떤 룰에 닿는지 계산한다. 표준 라이브러리만.

진짜 Wazuh 가 아니다. 다음은 재현하지 않는다(결과 해석 시 감안):
- 빈도 룰(frequency/timeframe — F1·F2 버스트)
- Wazuh 기본 웹 룰(31100 등)의 디코딩 실패 판정: 이 도구는 접근 로그로 읽히는 줄은 모두 부모 조건을 만족한다고 본다
- 룰 우선순위 세부(여러 룰이 닿으면 가장 깊은 자식 룰, 같으면 level 높은 쪽을 알럿으로 본다)
"""
import re
from pathlib import Path

PARENTS = {"31100", "31101", "31108", "31120", "31121", "31122", "31123"}  # Wazuh 기본 웹 룰 — 항상 참으로 본다
_RULE = re.compile(r'<rule\s+id="(\d+)"\s+level="(\d+)"([^>]*)>(.*?)</rule>', re.S)
_ACCESS = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)(?: HTTP/[\d.]+)?" (\d{3}) ')


def _field(body: str, tag: str):
    out = []
    for m in re.finditer(rf'<{tag}([^>]*)>([^<]*)</{tag}>', body):
        out.append((re.compile(m.group(2)), 'negate="yes"' in m.group(1)))
    return out


def load_rules(xml_path: str) -> list[dict]:
    text = Path(xml_path).read_text(encoding="utf-8")
    rules = []
    for m in _RULE.finditer(text):
        attrs, body = m.group(3), re.sub(r"<mitre>.*?</mitre>", "", m.group(4), flags=re.S)  # <mitre><id> 를 응답코드 조건으로 오인하지 않게
        sid = re.search(r"<if_sid>([^<]*)</if_sid>", body)
        grp = re.search(r"<if_group>([^<]*)</if_group>", body)
        rules.append({
            "id": m.group(1), "level": int(m.group(2)), "desc": (re.search(r"<description>([^<]*)</description>", body) or [None, ""])[1],
            "burst": "frequency=" in attrs,
            "if_sid": {s.strip() for s in sid.group(1).split(",")} if sid else None,
            "if_group": grp.group(1).strip() if grp else None,
            "url": _field(body, "url"), "protocol": _field(body, "protocol"), "id_f": _field(body, "id"),
            "groups": [g for g in re.findall(r"<group>([^<]*)</group>", body) for g in g.split(",") if g],
        })
    return rules


def classify(rules: list[dict], method: str, url: str, status: str):
    """이벤트가 닿는 가장 깊은 룰(dict) 또는 None. 빈도 룰은 건너뛴다."""
    ev = {"url": url, "protocol": method, "id_f": status}
    matched: dict[str, tuple[dict, int]] = {}
    groups: set[str] = set()
    progress = True
    while progress:
        progress = False
        for r in rules:
            if r["burst"] or r["id"] in matched:
                continue
            depth = 0
            if r["if_sid"] is not None:
                real = r["if_sid"] - PARENTS
                if real and not (real & matched.keys()):
                    continue
                depth = 1 + max([matched[s][1] for s in real & matched.keys()], default=0)
            if r["if_group"] is not None:
                if r["if_group"] not in groups:
                    continue
                depth = max(depth, 1 + max((d for rr, d in matched.values() if r["if_group"] in rr["groups"]), default=0))
            if not all(bool(rx.search(ev[k])) != neg for k in ("url", "protocol", "id_f") for rx, neg in r[k]):
                continue
            matched[r["id"]] = (r, depth)
            groups.update(r["groups"])
            progress = True
    alerting = [(d, r["level"], r) for r, d in matched.values() if r["level"] > 0]
    return max(alerting, key=lambda t: (t[0], t[1]))[2] if alerting else None


def parse_access(line: str):
    """(ip, 시각문자열, 메서드, url, 상태코드) 또는 None(요청 줄이 접근 로그 형식이 아님)."""
    m = _ACCESS.match(line)
    return (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)) if m else None

"""알럿에서 '코드로 확정할 수 있는 사실'을 계산한다 — LLM 은 이걸 설명·정리만 한다.

원칙: 명세 안/밖, 응답 코드의 의미, 후속(빈도) 룰, 같은 IP 묶음처럼 결정론으로 되는 건 LLM 에 추측시키지 않는다.
명세·예외 목록은 코퍼스의 0915 룰 파일 머리 주석에서 읽는다(룰이 생성된 때의 명세 그대로).
"""
import re
from collections import Counter
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
SPEC_FILE = "0915-shadow_api_rules.xml"
_STATUS = [
    (r"2\d\d", "성공(2xx)", "요청이 처리돼 응답이 나갔다 — 데이터가 노출됐을 수 있다"),
    (r"40[13]", "거부(401/403)", "접근이 막혔다 — 시도는 있었지만 성공하지 않았다"),
    (r"40[45]", "없는 경로·메서드(404/405)", "존재 여부를 더듬는 정찰 패턴"),
    (r"5\d\d", "서버 오류(5xx)", "서버가 오류를 냈다 — 입력이 비정상적으로 처리됐을 수 있다"),
]


def status_meaning(status) -> tuple[str, str] | None:
    s = str(status)
    for pat, name, why in _STATUS:
        if re.fullmatch(pat, s):
            return name, why
    return None


# ---- 명세 ----------------------------------------------------------------
def _norm(path: str) -> str:
    return (path.split("?")[0].rstrip("/")) or "/"


def load_spec(corpus: Path = CORPUS):
    """(허용 (메서드, 경로정규식) 목록, 예외 경로 집합) — 0915 머리 주석에서."""
    text = (corpus / SPEC_FILE).read_text(encoding="utf-8")
    head = re.match(r"\s*((?:<!--(?:(?!-->).)*-->\s*)+)", text, re.S)
    head = head.group(1) if head else ""
    allowed = []
    for m in re.finditer(r"(?m)^\s+(GET|POST|PUT|PATCH|DELETE)\s+(/\S*)\s*$", head):
        pat = re.sub(r"\\\{[^}]+\\\}", r"\\d+", re.escape(m.group(2)))
        allowed.append((m.group(1), re.compile(pat)))
    exc = set()
    em = re.search(r"예외[^\n]*:\s*GET\s+([^\n]+)", head)
    if em:
        exc = {_norm(p.strip()) for p in em.group(1).split("·") if p.strip().startswith("/")}
    return allowed, exc


def spec_status(method: str, path: str, spec=None) -> str:
    """'in_spec' | 'exception' | 'out_of_spec' | 'unknown'"""
    allowed, exc = spec or load_spec()
    if not allowed:
        return "unknown"
    p = _norm(path)
    if method.upper() == "GET" and p in exc:
        return "exception"
    return "in_spec" if any(m == method.upper() and rx.fullmatch(p) for m, rx in allowed) else "out_of_spec"


# ---- 룰 ------------------------------------------------------------------
_RULE = re.compile(r'<rule\s+id="(\d+)"\s+level="(\d+)"([^>]*)>(.*?)</rule>', re.S)


def load_rules(corpus: Path = CORPUS) -> dict[str, dict]:
    rules = {}
    for p in sorted(corpus.glob("*.xml")):
        for m in _RULE.finditer(p.read_text(encoding="utf-8")):
            attrs, body = m.group(3), m.group(4)
            g = lambda tag: (re.search(rf"<{tag}[^>]*>([^<]*)</{tag}>", body) or [None, None])[1]  # noqa: E731
            rules[m.group(1)] = {
                "id": m.group(1), "level": int(m.group(2)), "file": p.stem,
                "frequency": (re.search(r'frequency="(\d+)"', attrs) or [None, None])[1],
                "timeframe": (re.search(r'timeframe="(\d+)"', attrs) or [None, None])[1],
                "if_matched_sid": g("if_matched_sid"), "if_sid": g("if_sid"), "if_group": g("if_group"),
                "description": g("description"), "mitre": re.findall(r"<mitre>\s*<id>([^<]+)</id>", body),
            }
    return rules


def followups(rule_id: str, rules: dict) -> list[dict]:
    """이 룰이 쌓이면 울리는 빈도 룰."""
    return [r for r in rules.values() if r["if_matched_sid"] and rule_id in r["if_matched_sid"].replace(" ", "").split(",")]


# ---- 알럿 → 사실 ---------------------------------------------------------
def compute(alert: dict, batch: list[dict] | None = None) -> dict:
    """{'lines': [사실 문장…], 'signals': {...}, 'verdict': '의심'|'오탐 가능'|'보류'}"""
    rid = str(alert["rule"]["id"])
    d = alert.get("data", {})
    method, path, status, ip = d.get("method", ""), d.get("path", d.get("url", "")), d.get("status", d.get("id", "")), d.get("client_ip", d.get("srcip", ""))
    rules = load_rules()
    rule = rules.get(rid)
    lines, sig = [], {}

    st = status_meaning(status)
    if st:
        lines.append(f"응답 코드 {status} = {st[0]}: {st[1]}.")
        sig["status_class"] = st[0]
    if method and path:
        ss = spec_status(method, path)
        sig["spec"] = ss
        lines.append({
            "out_of_spec": f"{method} {_norm(path)} 는 API 명세에 없는 호출이다(명세 밖) — 이 룰 계열이 울리는 전제 조건.",
            "in_spec": f"{method} {_norm(path)} 는 명세 안의 호출이다 — 그런데 알럿이 났으니 룰과 명세가 어긋났는지 확인해야 한다.",
            "exception": f"GET {_norm(path)} 는 명세 예외 목록(FastAPI 공개 문서 화면)과 일치한다 — 이 예외는 정상 사용자(개발자) 접근에서 난 오탐을 막으려고 추가한 것이다.",
            "unknown": "명세를 읽지 못해 명세 안/밖을 판정할 수 없다.",
        }[ss])
    if rule:
        extra = f", MITRE {', '.join(rule['mitre'])}" if rule["mitre"] else ""
        lines.append(f"룰 {rid}: level {rule['level']}{extra}, 파일 {rule['file']}.")
        for f in followups(rid, rules):
            seen = ""
            if batch and ip:
                n = sum(1 for a in batch if str(a["rule"]["id"]) == rid
                        and a.get("data", {}).get("client_ip", a.get("data", {}).get("srcip")) == ip)
                need = int(f["frequency"] or 0)
                seen = f" 입력 안에서 이 출발지의 룰 {rid} 알럿은 {n}건으로 임계({need}회) {'이상' if n >= need else '미만'}이다."
            lines.append(f"후속 룰 {f['id']} (level {f['level']}): 같은 출발지에서 {f['timeframe']}초 안에 {f['frequency']}회 이상 쌓이면 울린다 — {f['description']}.{seen}")
    else:
        lines.append(f"룰 {rid} 는 코퍼스에 정의가 없다.")

    if batch and ip:
        same = [a for a in batch if (a.get("data", {}).get("client_ip", a.get("data", {}).get("srcip")) == ip)]
        if len(same) > 1:
            ts = sorted(a["timestamp"] for a in same if "timestamp" in a)
            span = ""
            if len(ts) > 1:
                from datetime import datetime
                span = f", {(datetime.fromisoformat(ts[-1]) - datetime.fromisoformat(ts[0])).total_seconds():.0f}초 사이"
            by_rule = Counter(str(a["rule"]["id"]) for a in same)
            paths = {_norm(a["data"].get("path", "")) for a in same}
            lines.append(f"같은 출발지 {ip} 의 알럿이 입력 안에 {len(same)}건{span} 있다(룰별 {dict(by_rule)}, 서로 다른 경로 {len(paths)}개).")
            sig["burst"] = len(same)

    # 결정론 판정 단서 — 룰 계열이 명세 밖 호출을 다루는 경우만
    if sig.get("spec") == "exception":
        verdict = "오탐 가능"
    elif sig.get("spec") == "out_of_spec":
        verdict = "의심"
    else:
        verdict = "보류"
    return {"lines": lines, "signals": sig, "verdict": verdict}


if __name__ == "__main__":
    import json
    import sys
    for ln in compute(json.loads(sys.argv[1]))["lines"]:
        print("-", ln)

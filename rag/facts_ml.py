"""ML 이벤트(방어연습장 detector 의 `type: ml`)에서 코드로 확정할 수 있는 사실을 계산한다.

쓰는 값은 연습장 코드·문서에 이미 있는 정의와 정책뿐이다 — 평가 데이터에 맞춘 임계값을 새로 만들지 않는다.
- 창 = IP × 5분 (detector/pipeline.py), 점수는 그 창의 특징으로 채점한 값
- seq_id_run = 창 안에서 객체 ID 를 +1 씩 이어 조회한 가장 긴 길이 (detector/features_v2.py seq_run), 1 이면 순차 조회 없음
- 자동 차단 정책 = ML high 이고 창 요청이 LAB_BLOCK_MIN_REQ(기본 15)건 이상 (pipeline.py)
- 허용 목록 = LAB_ALLOW (기본 10.1.0.1, 헬스체크·모니터링) — 걸려도 차단하지 않고 기록만
룰 경보 대조는 '그 이벤트 시각까지'의 과거만 본다(이후 일어난 일을 근거로 쓰지 않는다).
"""
from datetime import datetime, timedelta

BLOCK_MIN_REQ = 15
ALLOW = {"10.1.0.1"}
WINDOW = timedelta(minutes=5)


def _ts(e):
    return datetime.fromisoformat(e["timestamp"])


def compute(ev: dict, batch: list[dict] | None = None) -> dict:
    """{'lines': [사실 문장…], 'signals': {...}, 'verdict': '의심'|'오탐 가능'|'보류'}"""
    ip, n, seq, lvl, score = ev["client_ip"], ev["n_req"], ev["seq_id_run"], ev["level"], ev["score"]
    t = _ts(ev)
    batch = batch or []
    sig = {"allowlisted": ip in ALLOW, "below_block_min": n < BLOCK_MIN_REQ, "seq": seq}
    lines = [f"ML 판정 {lvl}: 이 출발지의 5분 창을 채점한 점수 {score} (창 요청 {n}건, 연속 ID 최장 {seq})."]

    if n < BLOCK_MIN_REQ:
        lines.append(f"자동 차단 정책은 'ML high + 창 요청 {BLOCK_MIN_REQ}건 이상'이다. 이 창은 {n}건이라 미달 — 이 판정만으로는 차단되지 않고 경보로만 남는다.")
    else:
        lines.append(f"자동 차단 정책('ML high + 창 요청 {BLOCK_MIN_REQ}건 이상')의 요청 수 조건을 이 창({n}건)이 채운다.")

    if seq > 1:
        lines.append(f"연속 ID 최장 {seq}: 창 안에서 객체 ID 를 +1 씩 이어 조회한 흔적이 있다(순차 열거 모양).")
    elif seq == 1:
        lines.append("연속 ID 최장 1: 객체 ID 를 조회한 요청은 있으나 +1 씩 이어진 조회는 없다.")
    else:
        lines.append("연속 ID 최장 0: 이 창에는 객체 ID 를 조회한 요청 자체가 없다.")

    if sig["allowlisted"]:
        lines.append("이 출발지는 허용 목록(헬스체크·모니터링)에 있다 — 걸려도 차단하지 않고 기록만 한다.")

    past_rules = [e for e in batch if e.get("type") == "alert" and e.get("client_ip", e.get("data", {}).get("client_ip")) == ip
                  and t - WINDOW <= _ts(e) <= t]
    sig["rule_alerts"] = len(past_rules)
    if past_rules:
        ids = sorted({str(e["rule"]["id"]) for e in past_rules})
        top = max(e["rule"]["level"] for e in past_rules)
        lines.append(f"같은 출발지에 직전 5분 룰 경보 {len(past_rules)}건(룰 {', '.join(ids)}, 최고 level {top}) — ML 과 룰이 같은 방향이다.")
    else:
        lines.append("같은 출발지에 직전 5분 룰 경보가 없다 — ML 단독 판정이다.")

    past_ml = [e for e in batch if e.get("type") == "ml" and e["client_ip"] == ip and _ts(e) <= t]
    if len(past_ml) > 1:
        high = sum(e["level"] == "high" for e in past_ml)
        lines.append(f"이 출발지의 ML 창은 지금까지 {len(past_ml)}개, 그중 high {high}개.")
    sig["ml_windows"] = len(past_ml)

    # 코드 판정 단서 — 근거가 ML 단독이고 정책 미달·순차 없음이면 약한 근거로 본다 (새 임계값 없음: 정책값·정의만 사용)
    if sig["allowlisted"]:
        verdict = "오탐 가능"
    elif sig["rule_alerts"] or seq > 1 or n >= BLOCK_MIN_REQ:
        verdict = "의심"
    else:
        verdict = "오탐 가능"
    return {"lines": lines, "signals": sig, "verdict": verdict}


if __name__ == "__main__":
    import json
    import sys
    for ln in compute(json.loads(sys.argv[1]))["lines"]:
        print("-", ln)

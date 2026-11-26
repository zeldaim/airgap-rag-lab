#!/usr/bin/env python3
"""Ollama 속도 측정 — 같은 요청을 세 번 보내 프롬프트 처리 속도와 생성 속도(토큰/초)를 잰다. 표준 라이브러리만.

  docker compose run --rm app tools/bench_ollama.py
첫 호출은 모델을 메모리에 올리는 시간이 섞이므로 따로 표시하고, 평균은 2·3번째로 낸다. 값은 Ollama 가 응답에 담아 주는 시간(나노초)이다.
"""
import json
import os
import urllib.request

URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
LOG = "10.10.0.7 - - [22/Nov/2026:08:29:23 +0000] \"GET /orders/12 HTTP/1.1\" 200 312 \"-\" \"Mozilla/5.0 (api-defense-lab)\"\n"
PROMPT = ("다음 접속 로그 묶음에서 공격자가 정상 사용자와 다른 점을 5가지로 정리하고, 각각에 대해 탐지 조건을 한 줄로 써라.\n"
          + LOG * 60)


def once(seed: int) -> dict:
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": PROMPT}], "stream": False,
                       "options": {"temperature": 0, "seed": seed, "num_predict": 200}}).encode()
    req = urllib.request.Request(URL + "/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())


def main():
    rows = []
    for i in range(3):
        r = once(i)
        pe, pd = r.get("prompt_eval_count", 0), r.get("prompt_eval_duration", 1) / 1e9
        ge, gd = r.get("eval_count", 0), r.get("eval_duration", 1) / 1e9
        rows.append({"load_s": r.get("load_duration", 0) / 1e9, "prompt_tps": pe / pd if pd else 0, "gen_tps": ge / gd if gd else 0,
                     "total_s": r.get("total_duration", 0) / 1e9, "prompt_tokens": pe, "gen_tokens": ge})
        x = rows[-1]
        print(f"[{i + 1}] 모델 로드 {x['load_s']:.1f}s · 프롬프트 {x['prompt_tokens']}토큰 {x['prompt_tps']:.0f} tok/s · 생성 {x['gen_tokens']}토큰 {x['gen_tps']:.1f} tok/s · 전체 {x['total_s']:.1f}s", flush=True)
    steady = rows[1:]
    print(f"평균(2·3번째): 프롬프트 {sum(x['prompt_tps'] for x in steady) / 2:.0f} tok/s · 생성 {sum(x['gen_tps'] for x in steady) / 2:.1f} tok/s · 호출당 {sum(x['total_s'] for x in steady) / 2:.1f}s")


if __name__ == "__main__":
    main()

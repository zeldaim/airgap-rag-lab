#!/usr/bin/env python3
"""로컬 LLM 호출 — 표준 라이브러리만(urllib), 외부 네트워크 호출 없음. Ollama 가 대상.
reservoir-rtu-lab 의 app/report.py 에 쓴 것과 같은 패턴(코드는 새로, 방식은 재사용).

  python llm/client.py "질문"
"""
import json
import os
import sys
import urllib.error
import urllib.request


def generate(prompt: str, system: str | None = None, base_url: str | None = None, model: str | None = None,
            timeout: int = 180) -> str:
    base_url = base_url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
    model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct")
    messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        raise RuntimeError(f"로컬 LLM({base_url}) 연결 실패 — Ollama 가 안 떠 있거나 모델이 없을 수 있음: {e}") from e
    return resp.get("message", {}).get("content", "")


if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "한 문장으로 자기소개해줘."
    print(generate(q))

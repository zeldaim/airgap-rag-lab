#!/usr/bin/env python3
"""실행 환경 기록 — Python 버전, 로컬 LLM 서버가 가진 모델 목록(크기 포함). 표준 라이브러리만."""
import json
import os
import sys
import urllib.request

url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/tags"
print("python", sys.version.split()[0])
print("ollama", url)
for m in json.loads(urllib.request.urlopen(url, timeout=30).read())["models"]:
    print(f"  {m['name']:28} {m['size'] / 1e9:5.1f} GB")

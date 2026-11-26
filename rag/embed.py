"""로컬 임베딩 — Ollama /api/embed (bge-m3). 표준 라이브러리만, 외부 호출 없음."""
import json
import os
import urllib.error
import urllib.request


def embed(texts: list[str], base_url: str | None = None, model: str | None = None,
          batch: int = 8, timeout: int = 300) -> list[list[float]]:
    base_url = (base_url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
    model = model or os.environ.get("EMBED_MODEL", "bge-m3")
    out: list[list[float]] = []
    for i in range(0, len(texts), batch):
        body = json.dumps({"model": model, "input": texts[i:i + batch]}).encode()
        req = urllib.request.Request(base_url + "/api/embed", data=body,
                                     headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out += json.loads(r.read())["embeddings"]
        except (urllib.error.URLError, TimeoutError, ConnectionError, KeyError) as e:
            raise RuntimeError(f"임베딩 실패({base_url}, 모델 {model}) — Ollama 가 떠 있고 모델을 받아 뒀는지 확인: {e}") from e
    return out

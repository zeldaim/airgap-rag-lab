"""질문 → 벡터 검색 상위 k 청크."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from embed import embed  # noqa: E402
from store import collection  # noqa: E402


def search(query: str, k: int = 5) -> list[dict]:
    qv = embed([query])[0]
    r = collection().query(query_embeddings=[qv], n_results=k)
    return [{"id": i, "distance": d, "text": t, "meta": m}
            for i, d, t, m in zip(r["ids"][0], r["distances"][0], r["documents"][0], r["metadatas"][0])]

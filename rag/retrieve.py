"""질문 → 상위 k 청크. 벡터 / BM25 / 하이브리드(RRF).

- vector : bge-m3 임베딩 + Chroma (의미 검색)
- bm25   : 표준 라이브러리만으로 구현한 키워드 검색 (룰 ID·경로·메서드 같은 정확한 토큰에 강함)
- hybrid : 둘의 순위를 Reciprocal Rank Fusion 으로 합침 (점수 단위가 달라 순위만 쓴다)
"""
import math
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from embed import embed  # noqa: E402
from store import COLLECTION, collection  # noqa: E402

RRF_K = 60
POOL = 20  # 각 검색기가 합치기 전에 내놓는 후보 수


def tokenize(text: str) -> list[str]:
    """영문·숫자·언더스코어는 단어(룰 ID·경로 조각 포함), 한글은 글자 bigram."""
    text = text.lower()
    toks = re.findall(r"[a-z0-9_]+", text)
    for run in re.findall(r"[가-힣]+", text):
        toks += [run] if len(run) == 1 else [run[i:i + 2] for i in range(len(run) - 1)]
    return toks


class BM25:
    def __init__(self, ids: list[str], docs: list[str], k1: float = 1.5, b: float = 0.75):
        self.ids, self.k1, self.b = ids, k1, b
        self.tf = [Counter(tokenize(d)) for d in docs]
        self.len = [sum(c.values()) for c in self.tf]
        self.avg = sum(self.len) / len(self.len)
        df = Counter(t for c in self.tf for t in c)
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: str) -> list[float]:
        q = tokenize(query)
        out = []
        for tf, ln in zip(self.tf, self.len):
            s = 0.0
            for t in q:
                if t in tf:
                    s += self.idf[t] * tf[t] * (self.k1 + 1) / (tf[t] + self.k1 * (1 - self.b + self.b * ln / self.avg))
            out.append(s)
        return out


_bm25_cache: dict = {}   # 컬렉션 이름 → {n, idx, by_id}


def _bm25(name: str = COLLECTION) -> tuple[BM25, dict]:
    col = collection(name=name)
    n = col.count()
    c = _bm25_cache.get(name)
    if not c or c["n"] != n:
        r = col.get()
        c = _bm25_cache[name] = {"n": n, "idx": BM25(r["ids"], r["documents"]),
                                 "by_id": {i: (d, m) for i, d, m in zip(r["ids"], r["documents"], r["metadatas"])}}
    return c["idx"], c["by_id"]


def _vector(query: str, n: int, name: str = COLLECTION) -> list[str]:
    qv = embed([query])[0]
    return collection(name=name).query(query_embeddings=[qv], n_results=n)["ids"][0]


def _keyword(query: str, n: int, name: str = COLLECTION) -> list[str]:
    idx, _ = _bm25(name)
    sc = idx.scores(query)
    order = sorted(range(len(sc)), key=lambda i: -sc[i])
    return [idx.ids[i] for i in order[:n] if sc[i] > 0]


def search(query: str, k: int = 5, mode: str = "hybrid", name: str = COLLECTION) -> list[dict]:
    if mode == "vector":
        ranked = _vector(query, k, name)
    elif mode == "bm25":
        ranked = _keyword(query, k, name)
    else:
        fused: Counter = Counter()
        for lst in (_vector(query, POOL, name), _keyword(query, POOL, name)):
            for rank, cid in enumerate(lst):
                fused[cid] += 1 / (RRF_K + rank + 1)
        ranked = [cid for cid, _ in fused.most_common(k)]
    _, by_id = _bm25(name)
    return [{"id": cid, "text": by_id[cid][0], "meta": by_id[cid][1]} for cid in ranked]

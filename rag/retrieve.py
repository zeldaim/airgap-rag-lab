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


VIOLATIONS = 0   # 마지막 방어선이 걸러 낸 결과 수 — 0 이 아니면 검색기 안쪽 필터에 구멍이 있다는 뜻
_bm25_cache: dict = {}   # (컬렉션, 권한 범위) → {n, idx, by_id}. 범위를 키에 넣는 이유: 이름만 키로 쓰면 admin 이 만든 색인이 다음 사용자에게 재사용돼 샌다


def scope_key(principal):
    return None if principal is None else (int(principal["level"]), principal["tenant"])


def scope_where(principal):
    """principal = {"level": int, "tenant": str}. 문서의 acl_level <= level 이고 tenant 가 본인 것이거나 shared 일 때만 보인다. None 이면 필터 없음(기존 동작)."""
    if principal is None:
        return None
    return {"$and": [{"acl_level": {"$lte": int(principal["level"])}}, {"tenant": {"$in": [principal["tenant"], "shared"]}}]}


def allowed(meta, principal) -> bool:
    """최종 방어선 — 권한 표시가 없는 문서는 거부한다(fail closed)."""
    if principal is None:
        return True
    return int(meta.get("acl_level", 99)) <= int(principal["level"]) and meta.get("tenant") in (principal["tenant"], "shared")


def _bm25(name: str = COLLECTION, principal=None) -> tuple[BM25, dict]:
    col = collection(name=name)
    key = (name, scope_key(principal))
    n = col.count()
    c = _bm25_cache.get(key)
    if not c or c["n"] != n:
        r = col.get(where=scope_where(principal)) if principal is not None else col.get()
        c = _bm25_cache[key] = {"n": n, "idx": BM25(r["ids"], r["documents"]) if r["ids"] else None,
                                "by_id": {i: (d, m) for i, d, m in zip(r["ids"], r["documents"], r["metadatas"])}}
    return c["idx"], c["by_id"]


def _vector(query: str, n: int, name: str = COLLECTION, principal=None) -> list[str]:
    col = collection(name=name)
    qv = embed([query])[0]
    kw = {"where": scope_where(principal)} if principal is not None else {}
    return col.query(query_embeddings=[qv], n_results=max(1, min(n, col.count())), **kw)["ids"][0]


def _keyword(query: str, n: int, name: str = COLLECTION, principal=None) -> list[str]:
    idx, _ = _bm25(name, principal)
    if idx is None:
        return []
    sc = idx.scores(query)
    order = sorted(range(len(sc)), key=lambda i: -sc[i])
    return [idx.ids[i] for i in order[:n] if sc[i] > 0]


def search(query: str, k: int = 5, mode: str = "hybrid", name: str = COLLECTION, principal=None, enforce_final: bool = True) -> list[dict]:
    """principal 을 주면 벡터·BM25 양쪽 앞단에서 권한으로 거른다. enforce_final=False 는 안쪽 필터만 시험할 때(평가용)."""
    global VIOLATIONS
    if mode == "vector":
        ranked = _vector(query, k, name, principal)
    elif mode == "bm25":
        ranked = _keyword(query, k, name, principal)
    else:
        fused: Counter = Counter()
        for lst in (_vector(query, POOL, name, principal), _keyword(query, POOL, name, principal)):
            for rank, cid in enumerate(lst):
                fused[cid] += 1 / (RRF_K + rank + 1)
        ranked = [cid for cid, _ in fused.most_common(k)]
    _, by_id = _bm25(name, principal)
    out = [{"id": cid, "text": by_id[cid][0], "meta": by_id[cid][1]} for cid in ranked if cid in by_id]
    if enforce_final:
        kept = [h for h in out if allowed(h["meta"], principal)]
        VIOLATIONS += len(out) - len(kept)
        out = kept
    return out

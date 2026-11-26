#!/usr/bin/env python3
"""corpus/ 의 문서를 청크로 쪼개 임베딩하고 ChromaDB 에 넣는다 (매번 새로 만든다).

  python rag/ingest.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from chunker import load_corpus  # noqa: E402
from embed import embed  # noqa: E402
from store import collection  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DOMAINS = {"wazuh": (ROOT / "corpus", "wazuh_rules"), "ml": (ROOT / "corpus_ml", "ml_docs")}  # 도메인 → (코퍼스 폴더, 컬렉션)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "wazuh"
    corpus, name = DOMAINS[domain]
    chunks = load_corpus(corpus)
    print(f"[{domain}] 청크 {len(chunks)}개 ({sum(c['kind'] == 'rule' for c in chunks)} 룰 + "
          f"{sum(c['kind'] == 'header' for c in chunks)} 머리설명 + {sum(c['kind'] == 'section' for c in chunks)} 문서섹션)")
    vecs = embed([c["text"] for c in chunks])
    col = collection(reset=True, name=name)
    meta = [{k: v for k, v in c.items() if k in ("file", "kind", "rule_id", "level")} for c in chunks]
    col.add(ids=[c["id"] for c in chunks], documents=[c["text"] for c in chunks], embeddings=vecs, metadatas=meta)
    print(f"저장 완료: {col.count()}개, 벡터 차원 {len(vecs[0])}")


if __name__ == "__main__":
    main()

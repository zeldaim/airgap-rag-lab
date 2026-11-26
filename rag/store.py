"""ChromaDB 저장소 — 앱 컨테이너 안에서 파일로 저장(PersistentClient), 별도 서버·외부 호출 없음.
임베딩은 우리가 직접 넣는다(embedding_function 없음) — 안 그러면 Chroma 가 기본 모델을 인터넷에서 받으려 한다.
"""
import os

os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")  # 망분리 — 텔레메트리 전송 시도 자체를 끈다

import chromadb  # noqa: E402

DB_DIR = os.environ.get("CHROMA_DIR", "/data/chroma")
COLLECTION = "wazuh_rules"


def collection(reset: bool = False):
    client = chromadb.PersistentClient(path=DB_DIR)
    if reset:
        try:
            client.delete_collection(COLLECTION)
        except Exception:
            pass
    return client.get_or_create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

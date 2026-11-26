#!/usr/bin/env python3
"""무결성 매니페스트 — 로드맵 3번. 표준 라이브러리 + 컬렉션 읽기만.

  python rag/integrity.py build     코퍼스 파일 해시 · 인덱스 루트 해시 · 모델 다이제스트를 integrity/manifest.json 에 기록
  python rag/integrity.py verify    지금 상태가 매니페스트와 같은지 확인 (다르면 종료 코드 1)
  python rag/integrity.py demo      변조를 흉내 내서 검출되는지 보인다 (복사본만 건드린다)

무엇을 증명하나 / 못 하나
- 코퍼스 파일: 파일 바이트의 sha256. 바뀌면 검출된다.
- 인덱스: 청크마다 sha256(id + 텍스트)를 정렬해 이어 붙인 루트 해시. 문서 텍스트·청크 추가/삭제는 검출된다.
  **임베딩 벡터와 메타데이터는 해시하지 않는다** — 벡터만 바꿔 검색 순위를 조작하는 공격은 이 도구로 못 잡는다.
- 모델: Ollama 가 말하는 모델 다이제스트(manifest 해시)를 기록·대조한다. 가중치 파일을 우리가 다시 해시하지는 않는다 (Ollama 가 받을 때 확인).
- 매니페스트 자체의 변조는 이 도구가 아니라 서명(supply-chain/run.sh 가 cosign 으로 서명)이 막는다.
"""
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from store import collection  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "integrity" / "manifest.json"
DIRS = {"corpus": ROOT / "corpus", "corpus_ml": ROOT / "corpus_ml", "samples": ROOT / "samples"}
COLLECTIONS = ("wazuh_rules", "ml_docs")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_hashes() -> dict:
    return {f"{d}/{p.name}": sha(p.read_bytes()) for d, base in DIRS.items() if base.exists() for p in sorted(base.iterdir()) if p.is_file()}


def index_root(name: str, col=None) -> dict:
    col = col or collection(name=name)
    r = col.get()
    lines = sorted(f"{i}\t{sha(t.encode('utf-8'))}" for i, t in zip(r["ids"], r["documents"]))
    return {"chunks": len(lines), "root_sha256": sha("\n".join(lines).encode("utf-8"))}


def model_digests() -> dict:
    url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/tags"
    with urllib.request.urlopen(url, timeout=30) as r:
        return {m["name"]: m["digest"] for m in json.loads(r.read())["models"]}


def current() -> dict:
    return {"files": file_hashes(), "indexes": {n: index_root(n) for n in COLLECTIONS}, "models": model_digests()}


def build():
    m = current()
    MANIFEST.parent.mkdir(exist_ok=True)
    MANIFEST.write_text(json.dumps(m, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"매니페스트 기록: 파일 {len(m['files'])}개 · 인덱스 {len(m['indexes'])}개 · 모델 {len(m['models'])}개 → {MANIFEST.relative_to(ROOT)}")


def diff(want: dict, got: dict) -> list[str]:
    bad = []
    for k in sorted(set(want["files"]) | set(got["files"])):
        if want["files"].get(k) != got["files"].get(k):
            bad.append(f"파일 {k}: " + ("없음" if k not in got["files"] else "새로 생김" if k not in want["files"] else "해시 다름"))
    for k in want["indexes"]:
        if want["indexes"][k] != got["indexes"].get(k):
            bad.append(f"인덱스 {k}: 청크 {want['indexes'][k]['chunks']}→{got['indexes'].get(k, {}).get('chunks')} · 루트 해시 다름")
    for k in want["models"]:
        if want["models"][k] != got["models"].get(k):
            bad.append(f"모델 {k}: 다이제스트 다름")
    return bad


def verify() -> int:
    want = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad = diff(want, current())
    for b in bad:
        print("FAIL", b)
    print("무결성 OK — 매니페스트와 일치" if not bad else f"무결성 위반 {len(bad)}건")
    return 1 if bad else 0


def demo():
    want = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print("[기준] 변조 없음 →", "일치" if not diff(want, current()) else "불일치(먼저 build 필요)")
    # 1) 인덱스 안의 문서 한 줄을 바꾼 복사본 — 룰 level 을 12 → 3 으로 (오염 공격의 모양)
    src = collection(name="wazuh_rules")
    r = src.get()
    tmp = collection(reset=True, name="integrity_demo")
    tmp.add(ids=list(r["ids"]), documents=list(r["documents"]), metadatas=list(r["metadatas"]), embeddings=[list(map(float, e)) for e in src.get(include=["embeddings"])["embeddings"]])
    i = list(r["ids"]).index("0911-bola_enumeration::100923")
    vec = [list(map(float, src.get(ids=[r["ids"][i]], include=["embeddings"])["embeddings"][0]))]   # 벡터를 직접 넘긴다 — 안 넘기면 Chroma 가 기본 모델을 인터넷에서 받으려 한다(망분리에서 차단됨)
    tmp.update(ids=[r["ids"][i]], documents=[r["documents"][i].replace('level="12"', 'level="3"')], embeddings=vec)
    got = index_root("integrity_demo", tmp)
    print("[변조 1] 인덱스의 룰 100923 level 12→3:", "검출" if got["root_sha256"] != want["indexes"]["wazuh_rules"]["root_sha256"] else "검출 못 함")
    # 2) 청크 하나 추가 (가짜 운영 지침)
    tmp.add(ids=["x::poison"], documents=["가짜 운영 지침"], embeddings=[[0.0] * len(r["ids"] and src.get(include=["embeddings"])["embeddings"][0])])
    got = index_root("integrity_demo", tmp)
    print("[변조 2] 가짜 청크 추가:", "검출" if got["chunks"] != want["indexes"]["wazuh_rules"]["chunks"] else "검출 못 함")
    # 3) 코퍼스 파일 한 바이트 변조(메모리에서)
    p = DIRS["corpus"] / "0911-bola_enumeration.xml"
    changed = sha(p.read_bytes() + b" ")
    print("[변조 3] 코퍼스 파일 끝에 공백 1바이트:", "검출" if changed != want["files"]["corpus/0911-bola_enumeration.xml"] else "검출 못 함")
    # 4) 벡터만 바꾸기 — 이 도구의 한계
    tmp2 = collection(reset=True, name="integrity_demo")
    tmp2.add(ids=list(r["ids"]), documents=list(r["documents"]), metadatas=list(r["metadatas"]), embeddings=[[1.0] * 1024 for _ in r["ids"]])
    got = index_root("integrity_demo", tmp2)
    print("[변조 4] 문서는 그대로, 임베딩 벡터만 전부 교체:", "검출" if got["root_sha256"] != want["indexes"]["wazuh_rules"]["root_sha256"] else "검출 못 함 (알려진 한계 — 벡터는 해시하지 않는다)")
    try:
        import chromadb
        chromadb.PersistentClient(path=os.environ.get("CHROMA_DIR", "/data/chroma")).delete_collection("integrity_demo")
    except Exception:
        pass


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "build":
        build()
    elif cmd == "demo":
        demo()
    else:
        sys.exit(verify())

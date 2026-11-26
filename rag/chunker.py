"""문서 → 청크. 표준 라이브러리만.

- Wazuh 룰 XML: <rule> 하나 = 청크 하나 (바로 앞에 붙은 주석 포함) + 파일 머리 주석 = 'header' 청크
- Markdown: 1~2단계 제목(#, ##) 단위
청크 id 는 `파일이름::식별자` 형식 (룰은 룰 ID, 문서는 s1, s2 …, 머리 주석은 header).
"""
import re
from pathlib import Path

_COMMENT = r"<!--(?:(?!-->).)*-->"
_RULE = re.compile(
    rf'(?P<pre>{_COMMENT}\s*)?(?P<rule><rule\s+id="(?P<id>\d+)"\s+level="(?P<level>\d+)".*?</rule>)', re.S)
_HEADER = re.compile(rf"\s*((?:{_COMMENT}\s*)+)", re.S)  # 맨 앞 연속 주석 전부
_GROUP = re.compile(r'<group\s+name="([^"]+)"')


def chunk_xml(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    stem = path.stem
    out = []
    m = _HEADER.match(text)
    if m:
        out.append({"id": f"{stem}::header", "file": stem, "kind": "header", "text": f"[{path.name} 머리 설명]\n{m.group(1)}"})
    group = (_GROUP.search(text) or [None, ""])[1]
    for m in _RULE.finditer(text):
        body = (m.group("pre") or "") + m.group("rule")
        out.append({"id": f"{stem}::{m.group('id')}", "file": stem, "kind": "rule",
                    "rule_id": m.group("id"), "level": int(m.group("level")),
                    "text": f"[{path.name} · 룰 {m.group('id')} · level {m.group('level')} · group {group}]\n{body}"})
    return out


def chunk_md(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    stem = path.stem
    title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), stem)
    parts = re.split(r"(?m)^(?=#{1,2} )", text)
    out = []
    # 제목 한 줄뿐인 조각은 버린다(어차피 모든 청크에 제목 접두사가 붙는다)
    parts = [p for p in parts if p.strip() and not re.fullmatch(r"#\s[^\n]*\s*", p)]
    for i, part in enumerate(parts):
        out.append({"id": f"{stem}::s{i}", "file": stem, "kind": "section",
                    "text": f"[{path.name} · {title}]\n{part.strip()}"})
    return out


def load_corpus(corpus_dir: Path) -> list[dict]:
    chunks = []
    for p in sorted(corpus_dir.iterdir()):
        if p.suffix == ".xml":
            chunks += chunk_xml(p)
        elif p.suffix == ".md":
            chunks += chunk_md(p)
    return chunks


if __name__ == "__main__":
    import sys
    cs = load_corpus(Path(sys.argv[1] if len(sys.argv) > 1 else "corpus"))
    print(len(cs), "chunks; max chars", max(len(c["text"]) for c in cs))
    for c in cs[:5]:
        print("-", c["id"], c["kind"], len(c["text"]))

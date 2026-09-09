"""The knowledge index behind kb_search.

The whole point of vector #3: this index was built by pointing a crawler at
everything, so internal documents sit in the same index as the public ones.
Nothing about the retrieval is malicious — the classification metadata is right
there in each document. Vulnerable mode simply never reads it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "corpus"
_STOP = {"the", "a", "an", "is", "are", "of", "for", "to", "and", "or", "in",
         "on", "what", "how", "do", "does", "i", "you", "your", "we", "our",
         "can", "with", "about", "me", "tell", "any", "there", "it", "that"}


@dataclass
class Doc:
    path: Path
    title: str
    classification: str
    source: str
    body: str

    @property
    def name(self) -> str:
        return self.path.name


def _parse(path: Path) -> Doc:
    raw = path.read_text()
    meta: dict[str, str] = {}
    body = raw
    if raw.startswith("---"):
        _, front, body = raw.split("---", 2)
        for line in front.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
    return Doc(
        path=path,
        title=meta.get("title", path.stem),
        classification=meta.get("classification", "unknown"),
        source=meta.get("source", ""),
        body=body.strip(),
    )


def load_index() -> list[Doc]:
    return [_parse(p) for p in sorted(CORPUS_ROOT.rglob("*.md"))]


_INDEX: list[Doc] | None = None


def index() -> list[Doc]:
    global _INDEX
    if _INDEX is None:
        _INDEX = load_index()
    return _INDEX


def _score(doc: Doc, terms: list[str]) -> int:
    haystack = f"{doc.title}\n{doc.body}".lower()
    score = 0
    for t in terms:
        hits = haystack.count(t)
        if hits:
            # Title matches weigh more, as in any half-decent BM25 setup.
            score += hits + (5 if t in doc.title.lower() else 0)
    return score


def search(query: str, limit: int = 3, public_only: bool = False) -> list[Doc]:
    terms = [t for t in re.findall(r"[a-z0-9\-]+", query.lower())
             if t not in _STOP and len(t) > 2]
    pool = [d for d in index() if not public_only or d.classification == "public"]
    scored = [(s, d) for d in pool if (s := _score(d, terms)) > 0]
    scored.sort(key=lambda sd: (-sd[0], sd[1].name))
    return [d for _, d in scored[:limit]]

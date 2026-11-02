#!/usr/bin/env python3
"""Convert an arm's native retrieval output into the common RAG E2E ranking JSONL.

Accepted inputs (same shapes the BEIR v3/v5 runs used):
  --format trec  : TREC run lines ``qid Q0 docid rank score tag``
  --format beir  : BEIR results JSON ``{qid: {docid: score}}`` (beir.retrieval output)
Output rows (input of ``rag-e2e-generate.py --retrieval``), one per query in --queries order:
  {"query_id", "protocol_sha256", "ranking": [doc_id...]}
Ordering: score desc, then doc_id asc (deterministic ties). TREC rank column is ignored;
scores are authoritative. Queries absent from the run get
an empty ranking (never dropped). Unknown doc ids or query ids fail closed.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class AdapterError(ValueError):
    pass


def parse_trec(text: str) -> dict[str, dict[str, float]]:
    runs: dict[str, dict[str, float]] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 6:
            raise AdapterError(f"trec line {n}: expected 6 fields")
        qid, _q0, doc, _rank, score, _tag = parts
        try:
            value = float(score)
        except ValueError as exc:
            raise AdapterError(f"trec line {n}: bad score") from exc
        if doc in runs.setdefault(qid, {}):
            raise AdapterError(f"trec line {n}: duplicate doc {doc} for {qid}")
        runs[qid][doc] = value
    return runs


def parse_beir(text: str) -> dict[str, dict[str, float]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise AdapterError("beir results must be an object")
    out: dict[str, dict[str, float]] = {}
    for qid, docs in data.items():
        if not isinstance(docs, dict):
            raise AdapterError(f"beir query {qid}: scores must be an object")
        out[qid] = {}
        for doc, score in docs.items():
            if type(score) not in (int, float):
                raise AdapterError(f"beir query {qid}: bad score for {doc}")
            out[qid][doc] = float(score)
    return out


def adapt(runs, query_ids, doc_ids, protocol_sha256, k):
    if not SHA256.fullmatch(protocol_sha256):
        raise AdapterError("protocol_sha256 must be sha256:<64 hex>")
    unknown_q = set(runs) - set(query_ids)
    if unknown_q:
        raise AdapterError(f"run has unknown query ids: {sorted(unknown_q)[:5]}")
    rows = []
    for qid in query_ids:
        scores = runs.get(qid, {})
        for doc, s in scores.items():
            if doc not in doc_ids:
                raise AdapterError(f"query {qid}: unknown doc id {doc}")
            if not math.isfinite(s):
                raise AdapterError(f"query {qid}: non-finite score for {doc}")
        ranking = [d for d, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))][:k]
        rows.append({"query_id": qid, "protocol_sha256": protocol_sha256, "ranking": ranking})
    return rows


def read_ids(path: Path) -> list[str]:
    ids = [json.loads(l)["id"] for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(ids) != len(set(ids)):
        raise AdapterError(f"{path}: duplicate ids")
    return ids


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--format", choices=["trec", "beir"], required=True)
    p.add_argument("--run", type=Path, required=True)
    p.add_argument("--queries", type=Path, required=True)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--protocol-sha256", required=True)
    p.add_argument("--k", type=int, default=10)
    a = p.parse_args()
    try:
        text = a.run.read_text(encoding="utf-8")
        runs = parse_trec(text) if a.format == "trec" else parse_beir(text)
        rows = adapt(runs, read_ids(a.queries), set(read_ids(a.corpus)), a.protocol_sha256, a.k)
    except (OSError, ValueError, KeyError) as exc:
        print(f"adapter error: {exc}", file=sys.stderr)
        return 1
    for r in rows:
        print(json.dumps(r, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

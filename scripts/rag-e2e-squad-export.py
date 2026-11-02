#!/usr/bin/env python3
"""Export SQuAD 2.0 as campaign corpus / queries / qrels JSONL (schema of evaluate-rag-campaign.py).

Documents and ids are exactly those of ``rag-e2e-squad-inventory.py`` (same split rule, same
first-occurrence dedup). Queries = questions of the held-out ``test`` split (SQuAD dev file).
Qrels: relevance 1 for the query's own paragraph when answerable (the dedup survivor if the
paragraph was a duplicate); unanswerable (``is_impossible``) questions get no positive qrel and
``answerable=false``. Single public tenant/principal: SQuAD carries no access rights, so the
authority metrics are trivially satisfied and must not be reported as evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location("sq_inv", Path(__file__).with_name("rag-e2e-squad-inventory.py"))
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)

TENANT, PRINCIPAL = "squad", "public"


def dump(rows) -> bytes:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for r in rows).encode()


def export(train: dict, dev: dict, corpus_splits=("train", "dev", "test")):
    inventory, _ = inv.build(train, dev)
    by_hash = {r["content_sha256"]: r for r in inventory}
    text = {}
    for source, data in (("train_file", train), ("dev_file", dev)):
        for article in data["data"]:
            for para in article["paragraphs"]:
                text.setdefault(inv.sha(para["context"].encode("utf-8")), para["context"])
    corpus = [{"id": r["id"], "tenant": TENANT, "principals": [PRINCIPAL], "state": "active",
               "text": text[r["content_sha256"]], "content_sha256": r["content_sha256"], "split": r["split"]}
              for r in inventory if r["split"] in corpus_splits]
    in_corpus = {d["id"] for d in corpus}
    queries, qrels, seen = [], [], set()
    for article in dev["data"]:
        for para in article["paragraphs"]:
            doc = by_hash[inv.sha(para["context"].encode("utf-8"))]
            for qa in para["qas"]:
                if qa["id"] in seen:
                    raise ValueError(f"duplicate question id {qa['id']!r}")
                seen.add(qa["id"])
                answerable = not qa.get("is_impossible", False)
                if answerable and doc["id"] not in in_corpus:
                    raise ValueError("answerable query's paragraph excluded from corpus")
                queries.append({"id": qa["id"], "tenant": TENANT, "principal": PRINCIPAL, "text": qa["question"],
                                "answerable": answerable, "group": article["title"], "split": "test"})
                if answerable:
                    qrels.append({"query_id": qa["id"], "doc_id": doc["id"], "relevance": 1})
    return corpus, queries, qrels


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--train", type=Path, required=True)
    p.add_argument("--dev", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--corpus-splits", default="train,dev,test")
    a = p.parse_args()
    try:
        tb, db = a.train.read_bytes(), a.dev.read_bytes()
        corpus, queries, qrels = export(json.loads(tb), json.loads(db), tuple(a.corpus_splits.split(",")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"squad export error: {exc}", file=sys.stderr)
        return 1
    a.out_dir.mkdir(parents=True, exist_ok=True)
    stats = {"_inputs": {"train_sha256": inv.sha(tb), "dev_sha256": inv.sha(db)}, "corpus_splits": a.corpus_splits}
    for name, rows in (("corpus", corpus), ("queries", queries), ("qrels", qrels)):
        body = dump(rows)
        (a.out_dir / f"{name}.jsonl").write_bytes(body)
        stats[name] = {"path": f"{name}.jsonl", "sha256": inv.sha(body), "rows": len(rows)}
    stats["queries"]["answerable"] = sum(q["answerable"] for q in queries)
    (a.out_dir / "export-stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    print(json.dumps(stats, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the SQuAD 2.0 document inventory consumed by ``check-rag-dataset-inventory.py``.

Inputs: the pinned Stanford ``train-v2.0.json`` and ``dev-v2.0.json`` (see prereg *Pins*).
Document = one Wikipedia paragraph (``context``); family = article ``title``.
Split rule (prereg section Dataset): SQuAD dev articles -> ``test``; SQuAD train articles ->
``train`` or ``dev`` by ``int(sha256(title), 16) % 10 == 0`` (≈10 % of train articles to dev).
Exact duplicate paragraphs (same SHA-256) are kept once (first occurrence in train-then-dev file
order) and counted, never silently: the checker forbids duplicate content hashes.

Also writes a provenance stub. The training-overlap (contamination) audit is NOT performed here:
``training_overlap_audit_sha256`` stays ``PENDING`` and the campaign readiness gate stays closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

LICENSE = "CC-BY-SA-4.0 (SQuAD 2.0, Rajpurkar et al. 2018)"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def train_split(title: str) -> str:
    return "dev" if int(hashlib.sha256(title.encode()).hexdigest(), 16) % 10 == 0 else "train"


def build(train: dict, dev: dict) -> tuple[list[dict], dict]:
    rows, seen, dup = [], set(), {"train_file": 0, "dev_file": 0}
    titles: dict[str, str] = {}
    for source, data in (("train_file", train), ("dev_file", dev)):
        for article in data["data"]:
            title = article["title"]
            if titles.setdefault(title, source) != source:
                raise ValueError(f"article {title!r} appears in both SQuAD files")
            split = "test" if source == "dev_file" else train_split(title)
            for i, para in enumerate(article["paragraphs"]):
                digest = sha(para["context"].encode("utf-8"))
                if digest in seen:
                    dup[source] += 1
                    continue
                seen.add(digest)
                rows.append({"id": f"{title}#{i}", "family_id": title, "split": split,
                             "content_sha256": digest, "license": LICENSE, "authorized": True})
    return rows, dup


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--train", type=Path, required=True)
    p.add_argument("--dev", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True, help="inventory JSONL")
    p.add_argument("--provenance-out", type=Path, required=True)
    a = p.parse_args()
    try:
        tb, db = a.train.read_bytes(), a.dev.read_bytes()
        rows, dup = build(json.loads(tb), json.loads(db))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"squad inventory error: {exc}", file=sys.stderr)
        return 1
    body = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows)
    a.out.write_text(body, encoding="utf-8")
    prov = {
        "origin": "SQuAD 2.0 train-v2.0.json + dev-v2.0.json (rajpurkar.github.io/SQuAD-explorer)",
        "license": LICENSE,
        "split_author": "scripts/rag-e2e-squad-inventory.py (dev articles->test; sha256(title)%10==0->dev)",
        "training_overlap_audit_sha256": "PENDING",
        "_inputs": {"train_sha256": sha(tb), "dev_sha256": sha(db)},
        "_inventory_sha256": sha(body.encode()),
        "_duplicate_paragraphs_dropped": dup,
        "_status": "overlap/contamination audit not performed; readiness must stay closed",
    }
    a.provenance_out.write_text(json.dumps(prov, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

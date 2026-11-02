#!/usr/bin/env python3
"""Tests for SQuAD export and the fail-closed overlap audit (synthetic inputs, no download)."""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ex = load("ex", "rag-e2e-squad-export.py")
au = load("au", "rag-e2e-overlap-audit.py")
CTX = "the quick brown fox jumps over the lazy dog near the river bank today ok"
TRAIN = {"data": [{"title": "A", "paragraphs": [{"context": "alpha text", "qas": []},
                                                 {"context": CTX, "qas": []}]}]}
DEV = {"data": [{"title": "B", "paragraphs": [
    {"context": CTX, "qas": [{"id": "q1", "question": "who jumps?", "is_impossible": False}]},
    {"context": "beta text", "qas": [{"id": "q2", "question": "none?", "is_impossible": True},
                                      {"id": "q3", "question": "beta?", "is_impossible": False}]}]}]}


def test_export():
    corpus, queries, qrels = ex.export(TRAIN, DEV)
    assert [d["id"] for d in corpus] == ["A#0", "A#1", "B#1"]  # B#0 deduped onto A#1
    for d in corpus:
        assert ex.inv.sha(d["text"].encode()) == d["content_sha256"]
    assert {q["id"]: q["answerable"] for q in queries} == {"q1": True, "q2": False, "q3": True}
    assert all(q["split"] == "test" for q in queries)
    assert qrels == [{"query_id": "q1", "doc_id": "A#1", "relevance": 1},
                     {"query_id": "q3", "doc_id": "B#1", "relevance": 1}]


def test_export_rejects_missing_gold():
    try:
        ex.export(TRAIN, DEV, ("test",))
    except ValueError:
        return
    raise AssertionError("expected failure")


def test_audit_fails_closed():
    with tempfile.TemporaryDirectory() as t:
        dev, out = Path(t, "dev.json"), Path(t, "audit.json")
        dev.write_text(json.dumps(DEV))
        r = subprocess.run([sys.executable, ROOT / "scripts/rag-e2e-overlap-audit.py", "--dev", dev, "--out", out])
        assert r.returncode == 2
        rec = json.loads(out.read_text())
        assert rec["status"] == "PENDING" and rec["training_overlap_audit_sha256"] == "PENDING"


def test_audit_measures_with_index():
    idx = au.grams(CTX)
    res = au.audit(DEV, {"generator": idx, "judge": set()})
    assert res["generator"]["contexts"] == {"eligible": 1, "contaminated": 1, "rate": 1.0}
    assert res["judge"]["contexts"]["contaminated"] == 0


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f()
    print("ok")

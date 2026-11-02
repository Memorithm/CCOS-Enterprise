#!/usr/bin/env python3
"""Tests for the ranking adapter and SQuAD inventory builder (synthetic inputs, no download)."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "rag-campaign-smoke"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ad = load("ad", "rag-e2e-rank-adapter.py")
sq = load("sq", "rag-e2e-squad-inventory.py")
inv = load("inv", "check-rag-dataset-inventory.py")
P = "sha256:" + "a" * 64


def raises(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError("expected failure")


def test_adapter():
    qids = ad.read_ids(FIX / "queries.jsonl")
    docs = set(ad.read_ids(FIX / "corpus.jsonl"))
    trec = "q-fr Q0 acme-api 2 1.0 x\nq-fr Q0 acme-paris 1 2.0 x\nq-fr Q0 beta-lyon 3 1.0 x\n"
    runs = ad.parse_trec(trec)
    beir = ad.parse_beir(json.dumps({"q-fr": {"acme-api": 1, "acme-paris": 2.0, "beta-lyon": 1.0}}))
    a, b = ad.adapt(runs, qids, docs, P, 10), ad.adapt(beir, qids, docs, P, 10)
    assert a == b and len(a) == len(qids)
    assert a[0] == {"query_id": "q-fr", "protocol_sha256": P, "ranking": ["acme-paris", "acme-api", "beta-lyon"]}
    assert all(r["ranking"] == [] for r in a[1:])
    assert ad.adapt(runs, qids, docs, P, 1)[0]["ranking"] == ["acme-paris"]
    raises(ad.adapt, {"nope": {}}, qids, docs, P, 10)
    raises(ad.adapt, {"q-fr": {"ghost": 1.0}}, qids, docs, P, 10)
    raises(ad.adapt, {"q-fr": {"acme-api": float("nan")}}, qids, docs, P, 10)
    raises(ad.adapt, runs, qids, docs, "bad", 10)
    raises(ad.parse_trec, "q Q0 d 1 x t\n")
    raises(ad.parse_trec, "q Q0 d 1 1 t\nq Q0 d 2 1 t\n")


def art(title, ctxs):
    return {"title": title, "paragraphs": [{"context": c, "qas": []} for c in ctxs]}


def test_squad_inventory():
    titles = [f"T{i}" for i in range(40)]
    train = {"data": [art(t, [f"{t} p0", f"{t} p1", "shared boilerplate"]) for t in titles]}
    dev = {"data": [art("D0", ["d p0", "shared boilerplate"])]}
    rows, dup = sq.build(train, dev)
    assert dup == {"train_file": 39, "dev_file": 1}
    body = "".join(json.dumps(r) + "\n" for r in rows).encode()
    summary = inv.validate_inventory_bytes(body)
    assert summary["family_disjoint"] and set(summary["documents"]) == {"train", "dev", "test"}
    assert {r["split"] for r in rows if r["family_id"] == "D0"} == {"test"}
    raises(sq.build, train, {"data": [art("T0", ["x"])]})


if __name__ == "__main__":
    test_adapter()
    test_squad_inventory()
    print("ok")

#!/usr/bin/env python3
"""Smoke-fixture tests for the RAG E2E generator runner (no model, no download)."""

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


gen = load("gen", "rag-e2e-generate.py")
ev = load("ev", "evaluate-rag-campaign.py")


class Fake:
    def __init__(self, mode):
        self.mode = mode

    def count_tokens(self, text):
        return len(text.split())

    def generate(self, prompt, max_tokens):
        if self.mode == "raise":
            raise RuntimeError("OOM")
        if self.mode == "bad":
            return {"text": "x", "abstained": "no", "citations": [], "answer_tokens": 1}
        doc_id = prompt.split("[", 1)[1].split("]", 1)[0] if "[" in prompt else None
        if doc_id is None:
            return {"text": "", "abstained": True, "citations": [], "answer_tokens": 1}
        return {"text": "answer", "abstained": False, "citations": [{"doc_id": doc_id, "start": 0, "end": 4}], "answer_tokens": 2}


def inputs():
    rows = gen.read_jsonl(FIX / "lexical.jsonl")
    retrieval = [{"query_id": r["query_id"], "protocol_sha256": r["protocol_sha256"], "ranking": r["ranking"]} for r in rows]
    return retrieval, gen.read_jsonl(FIX / "queries.jsonl"), gen.read_jsonl(FIX / "corpus.jsonl")


def validate(rows):
    manifest = json.loads((FIX / "manifest.json").read_text(encoding="utf-8"))
    protocol = manifest["protocol"]
    queries = {q["id"]: q for q in gen.read_jsonl(FIX / "queries.jsonl")}
    docs = {d["id"]: d for d in gen.read_jsonl(FIX / "corpus.jsonl")}
    for row in rows:
        ev.evaluate_row(row, queries[row["query_id"]], docs, {}, {"total_claims": 0 if row["answer"]["abstained"] else 1, "supported_claims": 0, "answer_correct": False}, protocol, row["protocol_sha256"])


def check(mode, expect_status):
    retrieval, queries, corpus = inputs()
    rows = gen.run(retrieval, queries, corpus, Fake(mode), 10, 3072, 256)
    assert [r["query_id"] for r in rows] == [r["query_id"] for r in retrieval], "no silent skip"
    assert all(r["status"] == expect_status for r in rows), mode
    if expect_status == "error":
        assert all(r["answer"] == {"text": "", "abstained": True, "citations": []} for r in rows)
    validate(rows)
    for r in rows:
        assert set(r) == {"query_id", "status", "protocol_sha256", "ranking", "context_doc_ids", "answer",
                          "latency_ms", "context_tokens", "answer_tokens", "embedding_tokens"}


def main():
    check("ok", "ok")
    check("raise", "error")
    check("bad", "error")
    retrieval, queries, corpus = inputs()
    rows = gen.run(retrieval, queries, corpus, Fake("ok"), 10, 1, 256)
    assert all(r["context_doc_ids"] == [] and r["context_tokens"] == 0 for r in rows), "budget cap"
    print("rag-e2e generator runner tests passed")


if __name__ == "__main__":
    main()

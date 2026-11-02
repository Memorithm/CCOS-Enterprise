#!/usr/bin/env python3
"""Frozen generator-runner interface for the RAG E2E campaign (scaffold).

retrieval JSONL in -> schema-3 answer JSONL out, one row per input query, in input order.

Input row: {"query_id", "protocol_sha256", "ranking": [doc_id...], "embedding_tokens"?: int,
            "retrieval_latency_ms"?: number}
Output row: exactly the fields `scripts/evaluate-rag-campaign.py` validates.

The model is supplied by a backend object (``--backend module:factory``) with
``count_tokens(text) -> int`` and ``generate(prompt, max_tokens) -> dict`` returning
``{"text", "abstained", "citations": [{"doc_id", "start", "end"}], "answer_tokens"}``.
Any backend exception or malformed output yields a ``status: "error"`` abstention row with the
measured latency/tokens; no query is ever skipped. This script never downloads weights and has no
built-in model: a real campaign must pass a pinned backend recorded in the manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import time
from pathlib import Path

PROMPT = (
    "Answer the question using only the numbered sources. Cite sources by id. "
    "If the sources do not contain the answer, abstain.\n\n{sources}\n\nQuestion: {question}\nAnswer:"
)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_context(ranking, docs, k, context_budget, count_tokens):
    chosen, used, parts = [], 0, []
    for doc_id in ranking[:k]:
        block = f"[{doc_id}] {docs[doc_id]['text']}"
        cost = count_tokens(block)
        if used + cost > context_budget:
            break
        chosen.append(doc_id)
        used += cost
        parts.append(block)
    return chosen, used, "\n".join(parts)


def bind_citations(raw, docs, context):
    out = []
    for c in raw:
        doc_id, start, end = c["doc_id"], c["start"], c["end"]
        if doc_id not in context or type(start) is not int or type(end) is not int:
            raise ValueError("citation outside selected context")
        body = docs[doc_id]["text"].encode()
        if not 0 <= start < end <= len(body):
            raise ValueError("citation offsets out of range")
        out.append({"doc_id": doc_id, "start": start, "end": end,
                    "source_sha256": docs[doc_id]["content_sha256"], "quote_sha256": sha(body[start:end])})
    return out


def run_one(row, query, docs, backend, k, context_budget, answer_budget):
    t0 = time.perf_counter()
    base_latency = float(row.get("retrieval_latency_ms", 0))
    context, ctx_tokens, answer_tokens = [], 0, 0
    try:
        context, ctx_tokens, sources = build_context(row["ranking"], docs, k, context_budget, backend.count_tokens)
        out = backend.generate(PROMPT.format(sources=sources, question=query["text"]), answer_budget)
        answer_tokens = int(out["answer_tokens"])
        abstained = out["abstained"]
        if type(abstained) is not bool:
            raise ValueError("abstained must be bool")
        text = "" if abstained else str(out["text"]).strip()
        citations = [] if abstained else bind_citations(out["citations"], docs, context)
        if not abstained and not text:
            raise ValueError("empty non-abstention")
        status, answer = "ok", {"text": text, "abstained": abstained, "citations": citations}
    except Exception as exc:  # noqa: BLE001 - every failure is recorded, never skipped
        print(f"generation error {row.get('query_id')}: {type(exc).__name__}: {exc}", file=sys.stderr)
        status, answer = "error", {"text": "", "abstained": True, "citations": []}
    return {
        "query_id": row["query_id"], "status": status, "protocol_sha256": row["protocol_sha256"],
        "ranking": row["ranking"], "context_doc_ids": context, "answer": answer,
        "latency_ms": base_latency + (time.perf_counter() - t0) * 1000.0,
        "context_tokens": ctx_tokens, "answer_tokens": answer_tokens,
        "embedding_tokens": int(row.get("embedding_tokens", 0)),
    }


def run(retrieval, queries, corpus, backend, k, context_budget, answer_budget):
    qmap = {q["id"]: q for q in queries}
    docs = {d["id"]: d for d in corpus}
    return [run_one(r, qmap[r["query_id"]], docs, backend, k, context_budget, answer_budget) for r in retrieval]


def load_backend(spec: str):
    module, _, factory = spec.partition(":")
    return getattr(importlib.import_module(module), factory or "make_backend")()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--retrieval", type=Path, required=True)
    p.add_argument("--queries", type=Path, required=True)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--backend", required=True, help="module:factory returning a pinned backend")
    p.add_argument("--k", type=int, default=10)
    p.add_argument("--context-tokens", type=int, default=3072)
    p.add_argument("--answer-tokens", type=int, default=256)
    a = p.parse_args()
    rows = run(read_jsonl(a.retrieval), read_jsonl(a.queries), read_jsonl(a.corpus),
               load_backend(a.backend), a.k, a.context_tokens, a.answer_tokens)
    for row in rows:
        sys.stdout.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

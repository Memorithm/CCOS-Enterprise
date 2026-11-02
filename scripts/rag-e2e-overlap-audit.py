#!/usr/bin/env python3
"""Training-overlap (contamination) audit protocol for SQuAD 2.0 vs the pinned generator/judge.

A rigorous audit needs either (a) the models' training corpora, to test SQuAD test-split
paragraphs/questions for n-gram overlap, or (b) a validated black-box membership test run on the
pinned weights. Qwen2.5-7B-Instruct and Mistral-7B-Instruct-v0.3 do not publish their training
corpora; SQuAD contexts are Wikipedia, which is presumed present in both pretraining mixes.

This script FAILS CLOSED. Without ``--training-ngrams`` (one file of lower-cased whitespace
13-grams per model, hashed) it writes a PENDING record with the reason and exits 2; it never
emits ``training_overlap_audit_sha256``. With n-gram indexes it computes per-model overlap rates of
test-split questions and contexts and writes the audit artifact; its sha256 is the value for the
manifest. The 13-gram rule follows the GPT-3 / Llama-2 contamination reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

N = 13
MODELS = {"generator": "Qwen/Qwen2.5-7B-Instruct", "judge": "mistralai/Mistral-7B-Instruct-v0.3"}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def grams(text: str, n: int = N) -> set[str]:
    toks = text.lower().split()
    return {hashlib.sha256(" ".join(toks[i:i + n]).encode()).hexdigest() for i in range(len(toks) - n + 1)}


def overlap_rate(texts, index: set[str]) -> dict:
    eligible = hit = 0
    for t in texts:
        g = grams(t)
        if not g:
            continue
        eligible += 1
        hit += bool(g & index)
    return {"eligible": eligible, "contaminated": hit, "rate": (hit / eligible) if eligible else None}


def audit(dev: dict, indexes: dict[str, set[str]]) -> dict:
    contexts = [p["context"] for a in dev["data"] for p in a["paragraphs"]]
    questions = [q["question"] for a in dev["data"] for p in a["paragraphs"] for q in p["qas"]]
    return {role: {"model_id": MODELS[role], "contexts": overlap_rate(contexts, idx),
                   "questions": overlap_rate(questions, idx)} for role, idx in indexes.items()}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dev", type=Path, required=True, help="SQuAD dev-v2.0.json (= campaign test split)")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--training-ngrams", action="append", default=[], metavar="ROLE=PATH",
                   help="hashed 13-gram index of a model's training data (role: generator|judge)")
    a = p.parse_args()
    db = a.dev.read_bytes()
    base = {"protocol": "13-gram overlap, test split (SQuAD dev file)", "n": N, "models": MODELS,
            "dev_sha256": sha(db)}
    given = dict(s.split("=", 1) for s in a.training_ngrams)
    if set(given) != set(MODELS):
        rec = dict(base, status="PENDING", training_overlap_audit_sha256="PENDING",
                   reason="training corpora of the pinned generator and judge are not published; no "
                          "n-gram index available for every role, so overlap cannot be measured. "
                          "SQuAD contexts are Wikipedia and should be presumed seen in pretraining.")
        a.out.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        print("overlap audit PENDING: missing training n-gram index for "
              + ",".join(sorted(set(MODELS) - set(given))), file=sys.stderr)
        return 2
    indexes = {}
    for role, path in given.items():
        raw = Path(path).read_bytes()
        indexes[role] = {l for l in raw.decode().split() if l}
        base.setdefault("training_ngrams_sha256", {})[role] = sha(raw)
    rec = dict(base, status="COMPLETE", results=audit(json.loads(db), indexes))
    a.out.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    print(sha(a.out.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Blind adjudication kit for the RAG E2E campaign (schema 3).

Subcommands
  rubric-hash RUBRIC                      -> sha256:<hex> of the rubric bytes (LF, no trailing ws)
  export   --queries Q --corpus C --arm ID=RESULTS ... --seed S --packet OUT --key OUT [--gold G]
           G = JSONL {"query_id", "answers": [...]} (rag-e2e-squad-gold.py); when given, every
           answerable query must have >= 1 gold answer (fail closed), since queries.jsonl carries none.
           Shuffles every (arm, query) row with a fixed seed, writes a blind packet (no arm id)
           and a private key capturing result_sha256 at export time.
  import   --key K --reviews R --arm ID=RESULTS ... --rubric RUBRIC --adjudicator NAME --out J
           Binds reviews to the key; refuses missing/duplicate/unknown reviews and any result whose
           current hash differs from the hash captured at export (stale review).
  kappa    --primary R1 --secondary R2 [--threshold 0.6]
           Cohen's kappa on answer_correct over the shared review_ids; exit 3 when kappa < threshold
           (campaign must be reported INCONCLUSIVE per prereg).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location("ev", Path(__file__).with_name("evaluate-rag-campaign.py"))
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


class KitError(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise KitError(msg)


def read_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def write_jsonl(path, rows):
    Path(path).write_text("".join(ev.canonical(r).decode() + "\n" for r in rows), encoding="utf-8")


def rubric_hash(path):
    text = Path(path).read_bytes().decode("utf-8")
    need("\r" not in text, "rubric must use LF line endings")
    need(all(line == line.rstrip() for line in text.split("\n")), "rubric has trailing whitespace")
    return ev.sha(text.encode("utf-8"))


def parse_arms(specs):
    arms = {}
    for spec in specs:
        arm_id, sep, path = spec.partition("=")
        need(sep and arm_id and path, f"bad --arm {spec!r}")
        need(arm_id not in arms, f"duplicate arm {arm_id}")
        rows = read_jsonl(path)
        ids = [r["query_id"] for r in rows]
        need(len(set(ids)) == len(ids), f"{arm_id}: duplicate query_id")
        arms[arm_id] = {r["query_id"]: r for r in rows}
    need(arms, "at least one --arm required")
    return arms


def load_gold(path):
    gold = {}
    for r in read_jsonl(path):
        need(r["query_id"] not in gold, f"duplicate gold {r['query_id']}")
        need(isinstance(r["answers"], list) and all(isinstance(x, str) for x in r["answers"]),
             f"bad gold answers for {r['query_id']}")
        gold[r["query_id"]] = r["answers"]
    return gold


def export(queries, corpus, arms, seed, gold=None):
    qmap = {q["id"]: q for q in queries}
    if gold is not None:
        for q in queries:
            if q["answerable"]:
                need(gold.get(q["id"]), f"{q['id']}: answerable query has no gold answer")
    docs = {d["id"]: d for d in corpus}
    items = []
    for arm_id in sorted(arms):
        need(set(arms[arm_id]) == set(qmap), f"{arm_id}: results do not cover exactly the query set")
        for qid in sorted(qmap):
            items.append((arm_id, qid))
    random.Random(seed).shuffle(items)
    packet, key = [], []
    for n, (arm_id, qid) in enumerate(items):
        row, q = arms[arm_id][qid], qmap[qid]
        review_id = f"r{n:06d}"
        quotes = []
        for c in row["answer"]["citations"]:
            raw = docs[c["doc_id"]]["text"].encode() if c["doc_id"] in docs else b""
            quotes.append(raw[c["start"]:c["end"]].decode("utf-8", "replace"))
        packet.append({"review_id": review_id, "question": q["text"],
                       "gold_answers": (gold[qid] if gold is not None else q.get("gold_answers", []))
                       if q["answerable"] else "UNANSWERABLE",
                       "abstained": row["answer"]["abstained"], "answer": row["answer"]["text"],
                       "cited_quotes": quotes})
        key.append({"review_id": review_id, "arm_id": arm_id, "query_id": qid,
                    "result_sha256": ev.judgment_result_hash(arm_id, row)})
    return packet, key


def import_reviews(key, reviews, arms, rubric_sha, adjudicator):
    kmap = {k["review_id"]: k for k in key}
    need(len(kmap) == len(key), "duplicate review_id in key")
    seen, out = set(), []
    for r in reviews:
        rid = r.get("review_id")
        need(rid in kmap, f"unknown review_id {rid}")
        need(rid not in seen, f"duplicate review {rid}")
        seen.add(rid)
        k = kmap[rid]
        current = arms.get(k["arm_id"], {}).get(k["query_id"])
        need(current is not None, f"{rid}: result row missing")
        need(ev.judgment_result_hash(k["arm_id"], current) == k["result_sha256"],
             f"{rid}: result changed since export (stale review); re-adjudicate")
        need(type(r.get("answer_correct")) is bool, f"{rid}: answer_correct must be bool")
        tc, sc = r.get("total_claims"), r.get("supported_claims")
        need(type(tc) is int and type(sc) is int and 0 <= sc <= tc, f"{rid}: invalid claim counts")
        need((tc == 0) == current["answer"]["abstained"], f"{rid}: claims inconsistent with abstention")
        out.append({"adjudicator": adjudicator, "answer_correct": r["answer_correct"], "arm_id": k["arm_id"],
                    "blinded": True, "query_id": k["query_id"], "result_sha256": k["result_sha256"],
                    "rubric_sha256": rubric_sha, "supported_claims": sc, "total_claims": tc})
    need(seen == set(kmap), f"missing reviews: {len(set(kmap) - seen)}")
    out.sort(key=lambda j: (j["arm_id"], j["query_id"]))
    return out


def kappa(primary, secondary):
    a = {r["review_id"]: r["answer_correct"] for r in primary}
    b = {r["review_id"]: r["answer_correct"] for r in secondary}
    shared = sorted(set(a) & set(b))
    need(len(shared) >= 2, "need at least two shared reviews")
    n = len(shared)
    po = sum(a[i] == b[i] for i in shared) / n
    pa, pb = sum(a[i] for i in shared) / n, sum(b[i] for i in shared) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    k = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return {"n": n, "observed_agreement": po, "kappa": k}


def main(argv=None):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("rubric-hash"); s.add_argument("rubric")
    s = sub.add_parser("export")
    for f in ("queries", "corpus", "packet", "key"):
        s.add_argument(f"--{f}", required=True)
    s.add_argument("--arm", action="append", default=[]); s.add_argument("--seed", type=int, default=20261102)
    s.add_argument("--gold")
    s = sub.add_parser("import")
    for f in ("key", "reviews", "rubric", "adjudicator", "out"):
        s.add_argument(f"--{f}", required=True)
    s.add_argument("--arm", action="append", default=[])
    s = sub.add_parser("kappa")
    s.add_argument("--primary", required=True); s.add_argument("--secondary", required=True)
    s.add_argument("--threshold", type=float, default=0.6)
    a = p.parse_args(argv)
    try:
        if a.cmd == "rubric-hash":
            print(rubric_hash(a.rubric))
        elif a.cmd == "export":
            packet, key = export(read_jsonl(a.queries), read_jsonl(a.corpus), parse_arms(a.arm), a.seed,
                                 load_gold(a.gold) if a.gold else None)
            write_jsonl(a.packet, packet); write_jsonl(a.key, key)
        elif a.cmd == "import":
            write_jsonl(a.out, import_reviews(read_jsonl(a.key), read_jsonl(a.reviews), parse_arms(a.arm),
                                              rubric_hash(a.rubric), a.adjudicator))
        else:
            r = kappa(read_jsonl(a.primary), read_jsonl(a.secondary))
            r["reliable"] = r["kappa"] >= a.threshold
            print(json.dumps(r, sort_keys=True))
            return 0 if r["reliable"] else 3
    except (KitError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"adjudication error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

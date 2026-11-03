#!/usr/bin/env python3
"""Pinned LLM judge pass over a blind adjudication packet (prereg: Mistral-7B-Instruct-v0.3, temperature 0).

  python3 scripts/rag_e2e_mistral_judge.py --packet P --rubric R --prompt judge-prompt.v1.txt \
      --snapshot SNAP --out reviews.jsonl --raw-out raw.jsonl [--device cuda]

Frozen v1 rules (no tuning, no metrics computed here):
  * the frozen prompt (rubric text embedded) is the single user turn of the model's chat template;
    greedy decoding, max_new_tokens=128, bf16; the judge never sees an arm id (packet is blind);
  * the first {...} object in the output is parsed; answer_correct must be bool, claim counts ints;
  * rubric rule "total_claims = 0 iff abstained" is applied deterministically: abstained rows get
    total=supported=0 (the judge still decides answer_correct); a non-abstained row with total < 1,
    supported > total, or an unparsable reply is a PARSE FAILURE: kept in raw-out, NOT written to
    reviews, and the script exits 4 so `rag-e2e-adjudicate.py import` fails closed (missing reviews).
"""

from __future__ import annotations

import argparse
import json
import re
import sys

OBJ_RE = re.compile(r"\{[^{}]*\}", re.S)


def render(prompt: str, rubric: str, row: dict) -> str:
    gold = row["gold_answers"]
    gold = "UNANSWERABLE" if gold == "UNANSWERABLE" else json.dumps(gold, ensure_ascii=False)
    quotes = "\n".join(f"- {q}" for q in row["cited_quotes"]) or "(none)"
    return prompt.format(rubric=rubric.strip(), question=row["question"], gold=gold,
                         abstained="yes" if row["abstained"] else "no", answer=row["answer"] or "(empty)",
                         quotes=quotes)


def parse_review(text: str, row: dict):
    """Pure v1 parse rule. Returns a review dict or None (parse failure)."""
    m = OBJ_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    ac, tc, sc = obj.get("answer_correct"), obj.get("total_claims"), obj.get("supported_claims")
    if type(ac) is not bool:
        return None
    if row["abstained"]:
        tc = sc = 0
    elif type(tc) is not int or type(sc) is not int or tc < 1 or not 0 <= sc <= tc:
        return None
    return {"review_id": row["review_id"], "answer_correct": ac, "total_claims": tc, "supported_claims": sc,
            "note": str(obj.get("note", ""))[:500]}


def main(argv=None):
    ap = argparse.ArgumentParser()
    for f in ("packet", "rubric", "prompt", "snapshot", "out", "raw-out"):
        ap.add_argument(f"--{f}", required=True)
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args(argv)
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(a.snapshot)
    model = AutoModelForCausalLM.from_pretrained(a.snapshot, torch_dtype=torch.bfloat16).to(a.device).eval()
    prompt = open(a.prompt, encoding="utf-8").read()
    rubric = open(a.rubric, encoding="utf-8").read()
    rows = [json.loads(l) for l in open(a.packet, encoding="utf-8") if l.strip()]
    fails = 0
    with open(a.out, "w", encoding="utf-8") as out, open(a.raw_out, "w", encoding="utf-8") as raw:
        for row in rows:
            ids = tok.apply_chat_template([{"role": "user", "content": render(prompt, rubric, row)}],
                                          add_generation_prompt=True, return_tensors="pt").to(a.device)
            with torch.inference_mode():
                o = model.generate(ids, max_new_tokens=128, do_sample=False, temperature=None, top_p=None,
                                   top_k=None, pad_token_id=tok.eos_token_id)
            text = tok.decode(o[0, ids.shape[1]:], skip_special_tokens=True).strip()
            rev = parse_review(text, row)
            raw.write(json.dumps({"review_id": row["review_id"], "raw": text, "parsed": rev is not None},
                                 ensure_ascii=False, sort_keys=True) + "\n")
            if rev is None:
                fails += 1
            else:
                out.write(json.dumps(rev, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"judge rows={len(rows)} parsed={len(rows) - fails} parse_failures={fails}")
    return 4 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

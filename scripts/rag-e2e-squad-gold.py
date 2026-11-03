#!/usr/bin/env python3
"""Gold answers sidecar for blind adjudication: dev-v2.0.json -> JSONL {"query_id", "answers"}.

queries.jsonl (campaign schema) carries no gold text; the adjudication packet needs it.
answers = distinct `answers[].text` in file order (empty list for unanswerable questions).
"""

import argparse
import json


def gold_rows(dev):
    for art in dev["data"]:
        for para in art["paragraphs"]:
            for qa in para["qas"]:
                seen = []
                for a in qa.get("answers", []):
                    if a["text"] not in seen:
                        seen.append(a["text"])
                yield {"query_id": qa["id"], "answers": seen}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(a.dev, encoding="utf-8") as f:
        rows = list(gold_rows(json.load(f)))
    with open(a.out, "w", encoding="utf-8") as o:
        for r in rows:
            o.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"gold rows={len(rows)} answerable={sum(1 for r in rows if r['answers'])}")


if __name__ == "__main__":
    main()

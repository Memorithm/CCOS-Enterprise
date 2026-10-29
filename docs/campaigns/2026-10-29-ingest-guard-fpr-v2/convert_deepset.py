#!/usr/bin/env python3
"""Convert the pinned deepset/prompt-injections parquet files to the JSONL read by the FPR-v2
harness. Deterministic: files in sorted name order (test, then train), rows in file order.
Usage: python3 convert_deepset.py <dir with the two parquet files> > deepset-prompt-injections.jsonl
Requires pandas + pyarrow."""
import glob, json, os, sys
import pandas as pd

d = sys.argv[1]
for f in sorted(glob.glob(os.path.join(d, "*.parquet"))):
    split = "test" if os.path.basename(f).startswith("test") else "train"
    for i, r in pd.read_parquet(f).iterrows():
        print(json.dumps({"split": split, "row": int(i), "label": int(r.label), "text": r.text}, ensure_ascii=False))

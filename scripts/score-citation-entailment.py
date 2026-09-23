#!/usr/bin/env python3
"""Summarize independently reviewed citation entailment without conflating integrity with truth."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

LABELS={"entailed","not_entailed","insufficient"}
INTEGRITY={"verified","unresolved","failed"}
MAX_BYTES=64*1024*1024
MAX_CLAIMS=100_000

class EntailmentError(ValueError):pass
def require(c,m):
    if not c:raise EntailmentError(m)
def label(v,n,maxlen=1024):
    require(isinstance(v,str) and v==v.strip() and 0<len(v)<=maxlen,f"invalid {n}")
    require(not any(ord(ch)<32 for ch in v),f"invalid {n}")
    return v
def ratio(a,b):return a/b if b else None

def summarize(data:bytes)->dict:
    require(len(data)<=MAX_BYTES,"entailment artifact exceeds 64 MiB")
    ids=set();counts=Counter();review_assignments=0;unanimous=Counter();disputed=0
    for line_no,line in enumerate(data.splitlines(),1):
        if not line.strip():continue
        row=json.loads(line)
        require(isinstance(row,dict) and set(row)=={
            "claim_id","citation_id","integrity_status","claim_text","quote_sha256","judgments"
        },f"line {line_no}: unexpected/missing fields")
        cid=label(row["claim_id"],"claim_id");require(cid not in ids,f"line {line_no}: duplicate claim id");ids.add(cid)
        label(row["citation_id"],"citation_id");label(row["claim_text"],"claim_text",1024*1024)
        require(isinstance(row["quote_sha256"],str) and row["quote_sha256"].startswith("sha256:") and len(row["quote_sha256"])==71,f"line {line_no}: invalid quote hash")
        integrity=row["integrity_status"];require(integrity in INTEGRITY,f"line {line_no}: invalid integrity status")
        judgments=row["judgments"];require(isinstance(judgments,list) and len(judgments)>=2,f"line {line_no}: at least two entailment reviewers required")
        reviewers=set();labels=[]
        for judgment in judgments:
            require(isinstance(judgment,dict) and set(judgment)=={"reviewer","label"},f"line {line_no}: invalid judgment")
            reviewer=label(judgment["reviewer"],"reviewer");require(reviewer not in reviewers,f"line {line_no}: duplicate reviewer");reviewers.add(reviewer)
            verdict=judgment["label"];require(verdict in LABELS,f"line {line_no}: invalid entailment label");labels.append(verdict)
        review_assignments+=len(reviewers);counts[f"integrity:{integrity}"]+=1
        if all(value==labels[0] for value in labels):
            unanimous[labels[0]]+=1
        else:disputed+=1
        require(len(ids)<=MAX_CLAIMS,"claim ceiling exceeded")
    require(ids,"empty entailment artifact")
    independently_supported=unanimous["entailed"]
    verified_and_supported=0
    # second pass keeps the integrity/semantic conjunction explicit
    for line in data.splitlines():
        if not line.strip():continue
        row=json.loads(line);labels=[j["label"] for j in row["judgments"]]
        if row["integrity_status"]=="verified" and all(v=="entailed" for v in labels):
            verified_and_supported+=1
    return {
      "schema_version":1,"claims":len(ids),"review_assignments":review_assignments,
      "integrity_verified":counts["integrity:verified"],
      "integrity_unresolved":counts["integrity:unresolved"],
      "integrity_failed":counts["integrity:failed"],
      "unanimous_entailed":unanimous["entailed"],
      "unanimous_not_entailed":unanimous["not_entailed"],
      "unanimous_insufficient":unanimous["insufficient"],
      "disputed":disputed,
      "semantic_support_rate":ratio(independently_supported,len(ids)),
      "verified_and_semantically_supported":verified_and_supported,
      "verified_and_semantically_supported_rate":ratio(verified_and_supported,len(ids)),
      "integrity_implies_entailment":False
    }

def main():
    p=argparse.ArgumentParser();p.add_argument("judgments",type=Path);a=p.parse_args()
    try:
        with a.judgments.open("rb") as f:data=f.read(MAX_BYTES+1)
        report=summarize(data)
    except (OSError,json.JSONDecodeError,EntailmentError) as exc:
        print(f"entailment error: {exc}",file=sys.stderr);return 1
    print(json.dumps(report,sort_keys=True,separators=(",",":")));return 0
if __name__=="__main__":raise SystemExit(main())

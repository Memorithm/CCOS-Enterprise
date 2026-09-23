#!/usr/bin/env python3
"""Measure ANN ranking loss against exact search for the same frozen encoder."""

from __future__ import annotations
import argparse,json,statistics,sys
from pathlib import Path

MAX_BYTES=256*1024*1024
MAX_QUERIES=100_000
MAX_RANK=100_000
class AnnEvalError(ValueError):pass
def require(c,m):
    if not c:raise AnnEvalError(m)
def load(path:Path):
    with path.open("rb") as f:data=f.read(MAX_BYTES+1)
    require(len(data)<=MAX_BYTES,"ranking artifact exceeds 256 MiB")
    result={}
    for line_no,line in enumerate(data.splitlines(),1):
        if not line.strip():continue
        row=json.loads(line)
        require(isinstance(row,dict) and set(row)=={"query_id","ranking"},f"line {line_no}: unexpected/missing fields")
        q=row["query_id"];require(isinstance(q,str) and q and q not in result,f"line {line_no}: invalid/duplicate query")
        ranking=row["ranking"];require(isinstance(ranking,list) and len(ranking)<=MAX_RANK and all(isinstance(x,str) and x for x in ranking),f"line {line_no}: invalid ranking")
        require(len(set(ranking))==len(ranking),f"line {line_no}: duplicate document")
        result[q]=ranking;require(len(result)<=MAX_QUERIES,"query ceiling exceeded")
    require(result,"empty ranking artifact");return result
def score(exact,approx,k):
    require(type(k)is int and 1<=k<=1000,"k must be 1..1000")
    require(set(exact)==set(approx),"exact and ANN query populations differ")
    rows=[];overlaps=[];top1=[];rr=[]
    for q in sorted(exact):
        e=exact[q][:k];a=approx[q][:k];den=len(e)
        overlap=len(set(e)&set(a))/den if den else None
        if overlap is not None:overlaps.append(overlap)
        exact_top=exact[q][0] if exact[q] else None
        retained=bool(exact_top is not None and exact_top in a);top1.append(int(retained))
        reciprocal=0.0
        if exact_top is not None:
            reciprocal=next((1/(i+1) for i,doc in enumerate(approx[q]) if doc==exact_top),0.0)
        rr.append(reciprocal)
        rows.append({"query_id":q,"exact_topk":len(e),"ann_topk":len(a),"overlap_at_k":overlap,
                     "exact_top1_retained_at_k":retained,"exact_top1_reciprocal_rank_in_ann":reciprocal})
    return {"schema_version":1,"k":k,"queries":len(rows),
            "mean_exact_topk_overlap":statistics.fmean(overlaps) if overlaps else None,
            "exact_top1_retention_at_k":statistics.fmean(top1),
            "exact_top1_mean_reciprocal_rank_in_ann":statistics.fmean(rr),
            "rows":rows,
            "interpretation":"ANN approximation loss only; no encoder-quality or answer-quality claim"}
def main():
    p=argparse.ArgumentParser();p.add_argument("exact",type=Path);p.add_argument("approx",type=Path);p.add_argument("--k",type=int,default=10);a=p.parse_args()
    try:r=score(load(a.exact),load(a.approx),a.k)
    except (OSError,json.JSONDecodeError,AnnEvalError) as exc:print(f"ANN eval error: {exc}",file=sys.stderr);return 1
    print(json.dumps(r,sort_keys=True,separators=(",",":")));return 0
if __name__=="__main__":raise SystemExit(main())

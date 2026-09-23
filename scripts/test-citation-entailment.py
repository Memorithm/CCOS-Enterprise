#!/usr/bin/env python3
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/"scripts"/"score-citation-entailment.py"
spec=importlib.util.spec_from_file_location("ent",SCRIPT);m=importlib.util.module_from_spec(spec);assert spec.loader is not None;spec.loader.exec_module(m)
def row(cid,integrity,labels):
 return {"claim_id":cid,"citation_id":"c:"+cid,"integrity_status":integrity,"claim_text":"claim "+cid,
         "quote_sha256":"sha256:"+"a"*64,"judgments":[{"reviewer":f"r{i}","label":v} for i,v in enumerate(labels)]}
def enc(rows):return ("\n".join(json.dumps(x) for x in rows)+"\n").encode()
def test_integrity_never_becomes_entailment_automatically():
 r=m.summarize(enc([row("a","verified",["not_entailed","not_entailed"]),row("b","verified",["entailed","entailed"])]))
 assert r["integrity_verified"]==2 and r["unanimous_entailed"]==1
 assert r["verified_and_semantically_supported"]==1
 assert r["integrity_implies_entailment"] is False
def test_reviewer_disagreement_is_preserved():
 r=m.summarize(enc([row("a","verified",["entailed","not_entailed"])]))
 assert r["disputed"]==1 and r["semantic_support_rate"]==0
def test_single_reviewer_is_refused():
 try:m.summarize(enc([row("a","verified",["entailed"])]));raise AssertionError("single reviewer accepted")
 except m.EntailmentError as exc:assert "two entailment reviewers" in str(exc)
if __name__=="__main__":
 tests=[test_integrity_never_becomes_entailment_automatically,test_reviewer_disagreement_is_preserved,test_single_reviewer_is_refused]
 for t in tests:t()
 print(f"{len(tests)} entailment tests passed")

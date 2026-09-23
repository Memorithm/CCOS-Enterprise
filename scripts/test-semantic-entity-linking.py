#!/usr/bin/env python3
import hashlib,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"score-semantic-entity-linking.py"
spec=importlib.util.spec_from_file_location("link",SCRIPT)
module=importlib.util.module_from_spec(spec);assert spec.loader is not None;spec.loader.exec_module(module)

def sha(t):return "sha256:"+hashlib.sha256(t.encode()).hexdigest()
def relation(text,s,o):
    raw=text.encode();a=raw.index(s.encode());b=raw.index(o.encode(),a+len(s.encode()))
    return {"subject":s,"relation":"works_for","polarity":"affirmed","object":o,
            "subject_span":[a,a+len(s.encode())],"object_span":[b,b+len(o.encode())]}
def fixture():
    text="Alice works at Acme.";r=relation(text,"Alice","Acme")
    hold={"id":"c","language":"en","document_family":"f","text":text,"content_sha256":sha(text),
          "categories":["plain"],"annotations":[{"reviewer":"r1","relations":[r]},{"reviewer":"r2","relations":[r]}],"gold":[r]}
    gold={"case_id":"c","subject_span":r["subject_span"],"object_span":r["object_span"],
          "subject_entity":"person:alice","object_entity":"org:acme"}
    return (json.dumps(hold)+"\n").encode(),gold
def enc(rows):return ("\n".join(json.dumps(x) for x in rows)+"\n").encode()

def test_linking_accuracy_is_conditional_on_exact_mentions():
    h,g=fixture()
    p=dict(g);p["object_entity"]="org:wrong"
    report=module.score(h,enc([g]),enc([p]))
    assert report["mention_pair_coverage"]==1
    assert report["subject_entity_accuracy_on_matched"]==1
    assert report["object_entity_accuracy_on_matched"]==0
    assert report["entity_pair_accuracy_on_matched"]==0

def test_wrong_spans_do_not_receive_entity_credit():
    h,g=fixture()
    p=dict(g);p["subject_span"]=[1,5]
    report=module.score(h,enc([g]),enc([p]))
    assert report["exact_span_matched_pairs"]==0
    assert report["entity_pair_accuracy_on_matched"] is None
    assert report["missed_gold_mention_pairs"]==1
    assert report["spurious_prediction_pairs"]==1

def test_unknown_case_is_refused():
    h,g=fixture();p=dict(g);p["case_id"]="ghost"
    try:module.score(h,enc([g]),enc([p]));raise AssertionError("unknown case accepted")
    except module.LinkingError:pass

if __name__=="__main__":
    tests=[test_linking_accuracy_is_conditional_on_exact_mentions,test_wrong_spans_do_not_receive_entity_credit,test_unknown_case_is_refused]
    for t in tests:t()
    print(f"{len(tests)} entity-linking tests passed")

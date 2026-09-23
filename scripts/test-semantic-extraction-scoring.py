#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "score-semantic-extraction-holdout.py"
spec = importlib.util.spec_from_file_location("score", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def rel(text, subject, relation, polarity, obj):
    raw = text.encode()
    s = raw.index(subject.encode())
    o = raw.index(obj.encode(), s + len(subject.encode()))
    return {"subject":subject,"relation":relation,"polarity":polarity,"object":obj,
            "subject_span":[s,s+len(subject.encode())],"object_span":[o,o+len(obj.encode())]}


def fixture():
    a="Alice works at Acme."
    b="Élodie ne travaille pas chez Beta."
    ra=rel(a,"Alice","works_for","affirmed","Acme")
    rb=rel(b,"Élodie","works_for","negated","Beta")
    cases=[
      {"id":"a","language":"en","document_family":"fa","text":a,"content_sha256":sha(a),
       "categories":["plain"],"annotations":[{"reviewer":"r1","relations":[ra]},{"reviewer":"r2","relations":[ra]}],"gold":[ra]},
      {"id":"b","language":"fr","document_family":"fb","text":b,"content_sha256":sha(b),
       "categories":["negation"],"annotations":[{"reviewer":"r1","relations":[rb]},{"reviewer":"r2","relations":[]}],"gold":[rb]},
    ]
    preds=[
      {"case_id":"a","abstained":False,"relations":[ra]},
      {"case_id":"b","abstained":True,"relations":[]},
    ]
    enc=lambda rows: ("\n".join(json.dumps(x,ensure_ascii=False,sort_keys=True) for x in rows)+"\n").encode()
    return enc(cases),enc(preds)


def test_scoring_preserves_misses_and_strata():
    holdout,preds=fixture()
    report=module.score(holdout,preds)
    assert report["overall"]["tp"]==1
    assert report["overall"]["fn"]==1
    assert report["strata"]["language:fr"]["recall"]==0
    assert report["strata"]["category:negation"]["fn"]==1
    assert report["annotation_exact_agreement"]==0.5


def test_missing_prediction_is_refused():
    holdout,preds=fixture()
    one=preds.splitlines()[0]+b"\n"
    try:
        module.score(holdout,one)
        raise AssertionError("partial predictions accepted")
    except module.ScoreError as exc:
        assert "every holdout case" in str(exc)


def test_abstention_with_relation_is_refused():
    holdout,preds=fixture()
    rows=[json.loads(x) for x in preds.splitlines()]
    rows[0]["abstained"]=True
    bad=("\n".join(json.dumps(x) for x in rows)+"\n").encode()
    try:
        module.score(holdout,bad)
        raise AssertionError("contradictory abstention accepted")
    except module.ScoreError as exc:
        assert "abstention emitted relations" in str(exc)


if __name__=="__main__":
    tests=[test_scoring_preserves_misses_and_strata,test_missing_prediction_is_refused,test_abstention_with_relation_is_refused]
    for test in tests:test()
    print(f"{len(tests)} semantic-scoring tests passed")

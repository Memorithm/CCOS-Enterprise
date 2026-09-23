#!/usr/bin/env python3
"""Score entity linking separately from semantic relation extraction."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HOLDOUT=ROOT/"scripts"/"check-semantic-extraction-holdout.py"
spec=importlib.util.spec_from_file_location("holdout",HOLDOUT)
holdout=importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(holdout)


class LinkingError(ValueError):
    pass


def require(condition,message):
    if not condition:
        raise LinkingError(message)


def label(value,name):
    require(isinstance(value,str) and value==value.strip() and 0<len(value)<=1024,f"invalid {name}")
    require(not any(ord(c)<32 for c in value),f"invalid {name}")
    return value


def load_cases(data):
    holdout.validate_bytes(data,require_coverage=False)
    return {row["id"]:row for row in (json.loads(line) for line in data.splitlines() if line.strip())}


def span(value,raw,name):
    require(isinstance(value,list) and len(value)==2 and all(type(x)is int for x in value),f"invalid {name}")
    require(0<=value[0]<value[1]<=len(raw),f"invalid {name}")
    return tuple(value)


def load_links(data,cases,name):
    result={}
    for line_no,line in enumerate(data.splitlines(),1):
        if not line.strip():continue
        row=json.loads(line)
        require(isinstance(row,dict) and set(row)=={
            "case_id","subject_span","object_span","subject_entity","object_entity"
        },f"{name} line {line_no}: unexpected/missing fields")
        cid=row["case_id"]
        require(cid in cases,f"{name} line {line_no}: unknown case")
        raw=cases[cid]["text"].encode()
        key=(cid,span(row["subject_span"],raw,"subject_span"),span(row["object_span"],raw,"object_span"))
        require(key not in result,f"{name} line {line_no}: duplicate mention pair")
        result[key]=(label(row["subject_entity"],"subject_entity"),label(row["object_entity"],"object_entity"))
    return result


def score(holdout_data,gold_data,prediction_data):
    cases=load_cases(holdout_data)
    gold=load_links(gold_data,cases,"gold")
    predicted=load_links(prediction_data,cases,"prediction")
    require(gold,"empty entity-linking gold")
    matched=set(gold)&set(predicted)
    subject_correct=sum(predicted[key][0]==gold[key][0] for key in matched)
    object_correct=sum(predicted[key][1]==gold[key][1] for key in matched)
    pair_correct=sum(predicted[key]==gold[key] for key in matched)
    return {
        "schema_version":1,
        "gold_mention_pairs":len(gold),
        "predicted_mention_pairs":len(predicted),
        "exact_span_matched_pairs":len(matched),
        "mention_pair_coverage":len(matched)/len(gold),
        "subject_entity_accuracy_on_matched":subject_correct/len(matched) if matched else None,
        "object_entity_accuracy_on_matched":object_correct/len(matched) if matched else None,
        "entity_pair_accuracy_on_matched":pair_correct/len(matched) if matched else None,
        "missed_gold_mention_pairs":len(set(gold)-set(predicted)),
        "spurious_prediction_pairs":len(set(predicted)-set(gold)),
    }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("holdout",type=Path)
    parser.add_argument("gold",type=Path)
    parser.add_argument("predictions",type=Path)
    args=parser.parse_args()
    try:
        report=score(args.holdout.read_bytes(),args.gold.read_bytes(),args.predictions.read_bytes())
    except (OSError,json.JSONDecodeError,holdout.HoldoutError,LinkingError) as exc:
        print(f"entity linking score error: {exc}",file=sys.stderr)
        return 1
    print(json.dumps(report,sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())

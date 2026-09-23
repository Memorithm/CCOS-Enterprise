#!/usr/bin/env python3
"""Score semantic relation predictions on the independent holdout contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOLDOUT = ROOT / "scripts" / "check-semantic-extraction-holdout.py"
spec = importlib.util.spec_from_file_location("semantic_holdout", HOLDOUT)
holdout = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(holdout)


class ScoreError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScoreError(message)


def ratio(a: int, b: int):
    return a / b if b else None


def metrics(tp: int, fp: int, fn: int) -> dict:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
    }


def load_cases(data: bytes) -> dict[str, dict]:
    holdout.validate_bytes(data, require_coverage=False)
    cases = {}
    for line in data.splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        cases[case["id"]] = case
    return cases


def load_predictions(data: bytes, cases: dict[str, dict]) -> dict[str, dict]:
    predictions = {}
    for line_no, line in enumerate(data.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        require(
            isinstance(row, dict) and set(row) == {"case_id", "abstained", "relations"},
            f"prediction line {line_no}: unexpected/missing fields",
        )
        case_id = row["case_id"]
        require(isinstance(case_id, str) and case_id in cases, f"prediction line {line_no}: unknown case")
        require(case_id not in predictions, f"prediction line {line_no}: duplicate case")
        require(type(row["abstained"]) is bool, f"prediction line {line_no}: abstained must be bool")
        raw = cases[case_id]["text"].encode("utf-8")
        relation_set = holdout.validate_relations(row["relations"], raw, f"prediction {case_id}")
        require(not row["abstained"] or not relation_set, f"prediction {case_id}: abstention emitted relations")
        predictions[case_id] = {"relations": relation_set, "abstained": row["abstained"]}
    require(set(predictions) == set(cases), "predictions must cover every holdout case exactly once")
    return predictions


def score(holdout_data: bytes, prediction_data: bytes) -> dict:
    cases = load_cases(holdout_data)
    predictions = load_predictions(prediction_data, cases)
    totals = [0, 0, 0]
    grouped = defaultdict(lambda: [0, 0, 0, 0, 0])
    exact_agreements = 0

    for case_id in sorted(cases):
        case = cases[case_id]
        raw = case["text"].encode("utf-8")
        gold = holdout.validate_relations(case["gold"], raw, f"gold {case_id}")
        predicted = predictions[case_id]["relations"]
        tp = len(gold & predicted)
        fp = len(predicted - gold)
        fn = len(gold - predicted)
        totals[0] += tp
        totals[1] += fp
        totals[2] += fn
        expected_abstention = not gold
        abstention_correct = predictions[case_id]["abstained"] == expected_abstention

        annotation_sets = [
            holdout.validate_relations(annotation["relations"], raw, f"annotation {case_id}")
            for annotation in case["annotations"]
        ]
        exact_agreements += int(all(value == annotation_sets[0] for value in annotation_sets[1:]))

        keys = [f"language:{case['language']}"] + [f"category:{category}" for category in case["categories"]]
        for key in keys:
            bucket = grouped[key]
            bucket[0] += tp
            bucket[1] += fp
            bucket[2] += fn
            bucket[3] += int(abstention_correct)
            bucket[4] += 1

    result = {
        "schema_version": 1,
        "overall": metrics(*totals),
        "abstention_accuracy": ratio(
            sum(predictions[cid]["abstained"] == (not holdout.validate_relations(
                cases[cid]["gold"], cases[cid]["text"].encode("utf-8"), f"gold {cid}"
            )) for cid in cases),
            len(cases),
        ),
        "annotation_exact_agreement": ratio(exact_agreements, len(cases)),
        "strata": {},
    }
    for key in sorted(grouped):
        tp, fp, fn, abstention_correct, count = grouped[key]
        row = metrics(tp, fp, fn)
        row["cases"] = count
        row["abstention_accuracy"] = ratio(abstention_correct, count)
        result["strata"][key] = row
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("holdout", type=Path)
    parser.add_argument("predictions", type=Path)
    args = parser.parse_args()
    try:
        report = score(args.holdout.read_bytes(), args.predictions.read_bytes())
    except (OSError, json.JSONDecodeError, holdout.HoldoutError, ScoreError) as exc:
        print(f"semantic score error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

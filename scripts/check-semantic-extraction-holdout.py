#!/usr/bin/env python3
"""Validate an independently reviewed EN/FR semantic-extraction holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MAX_CASES = 100_000
RELATIONS = {"works_for", "located_in", "depends_on"}
POLARITIES = {"affirmed", "negated"}
CATEGORIES = {"plain", "paraphrase", "negation", "temporal", "entity_confusion", "abstention"}
REQUIRED_CATEGORIES = CATEGORIES
HASH = re.compile(r"sha256:[0-9a-f]{64}")


class HoldoutError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HoldoutError(message)


def label(value, name, maximum=512):
    require(isinstance(value, str) and value == value.strip() and 0 < len(value) <= maximum, f"invalid {name}")
    require(not any(ord(ch) < 32 for ch in value), f"invalid {name}")
    return value


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def relation_key(row: dict) -> tuple:
    return (
        row["subject"], row["relation"], row["polarity"], row["object"],
        tuple(row["subject_span"]), tuple(row["object_span"]),
    )


def validate_relation(row: object, raw: bytes, context: str) -> tuple:
    require(isinstance(row, dict), f"{context}: relation must be object")
    require(
        set(row) == {"subject", "relation", "polarity", "object", "subject_span", "object_span"},
        f"{context}: unexpected/missing relation fields",
    )
    subject = label(row["subject"], f"{context} subject")
    obj = label(row["object"], f"{context} object")
    require(row["relation"] in RELATIONS, f"{context}: invalid relation")
    require(row["polarity"] in POLARITIES, f"{context}: invalid polarity")
    for name, expected in (("subject_span", subject), ("object_span", obj)):
        span = row[name]
        require(
            isinstance(span, list)
            and len(span) == 2
            and all(type(v) is int for v in span)
            and 0 <= span[0] < span[1] <= len(raw),
            f"{context}: invalid {name}",
        )
        try:
            actual = raw[span[0]:span[1]].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HoldoutError(f"{context}: span splits UTF-8") from exc
        require(actual == expected, f"{context}: {name} does not match raw source bytes")
    return relation_key(row)


def validate_relations(rows: object, raw: bytes, context: str) -> set[tuple]:
    require(isinstance(rows, list), f"{context}: relations must be list")
    keys = set()
    for index, row in enumerate(rows):
        key = validate_relation(row, raw, f"{context}[{index}]")
        require(key not in keys, f"{context}: duplicate relation")
        keys.add(key)
    return keys


def validate_bytes(data: bytes, require_coverage: bool = True) -> dict:
    require(len(data) <= MAX_BYTES, "holdout exceeds 64 MiB")
    ids = set()
    languages = Counter()
    categories = Counter()
    families = Counter()
    cases = 0
    total_gold = 0
    reviewer_pairs = 0

    for line_no, line in enumerate(data.splitlines(), 1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HoldoutError(f"line {line_no}: invalid JSON: {exc}") from exc
        require(isinstance(case, dict), f"line {line_no}: case must be object")
        require(set(case) == {
            "id", "language", "document_family", "text", "content_sha256",
            "categories", "annotations", "gold"
        }, f"line {line_no}: unexpected/missing fields")
        case_id = label(case["id"], f"line {line_no} id")
        require(case_id not in ids, f"line {line_no}: duplicate case id")
        ids.add(case_id)
        require(case["language"] in {"en", "fr"}, f"line {line_no}: language must be en/fr")
        family = label(case["document_family"], f"line {line_no} document_family")
        text = case["text"]
        require(isinstance(text, str) and text, f"line {line_no}: empty text")
        raw = text.encode("utf-8")
        require(isinstance(case["content_sha256"], str) and HASH.fullmatch(case["content_sha256"]), f"line {line_no}: invalid content hash")
        require(digest(raw) == case["content_sha256"], f"line {line_no}: content hash mismatch")
        case_categories = case["categories"]
        require(
            isinstance(case_categories, list)
            and case_categories
            and len(set(case_categories)) == len(case_categories)
            and all(category in CATEGORIES for category in case_categories),
            f"line {line_no}: invalid categories",
        )
        gold = validate_relations(case["gold"], raw, f"line {line_no} gold")
        if "abstention" in case_categories:
            require(not gold, f"line {line_no}: abstention case has gold relations")
        annotations = case["annotations"]
        require(isinstance(annotations, list) and len(annotations) >= 2, f"line {line_no}: at least two independent annotations required")
        reviewers = set()
        for index, annotation in enumerate(annotations):
            require(
                isinstance(annotation, dict) and set(annotation) == {"reviewer", "relations"},
                f"line {line_no}: invalid annotation",
            )
            reviewer = label(annotation["reviewer"], f"line {line_no} reviewer")
            require(reviewer not in reviewers, f"line {line_no}: duplicate reviewer")
            reviewers.add(reviewer)
            validate_relations(annotation["relations"], raw, f"line {line_no} annotation[{index}]")
        reviewer_pairs += len(reviewers)
        cases += 1
        require(cases <= MAX_CASES, "holdout case ceiling exceeded")
        total_gold += len(gold)
        languages[case["language"]] += 1
        families[family] += 1
        for category in case_categories:
            categories[category] += 1

    require(cases > 0, "empty holdout")
    if require_coverage:
        require(set(languages) == {"en", "fr"}, "holdout must cover English and French")
        require(REQUIRED_CATEGORIES.issubset(categories), "holdout misses required challenge categories")
    return {
        "schema_version": 1,
        "holdout_sha256": digest(data),
        "cases": cases,
        "gold_relations": total_gold,
        "languages": dict(sorted(languages.items())),
        "categories": dict(sorted(categories.items())),
        "document_families": len(families),
        "annotation_assignments": reviewer_pairs,
        "independent_reviewers_per_case_min": 2,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("holdout", type=Path)
    args = parser.parse_args()
    try:
        with args.holdout.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        report = validate_bytes(data)
    except (OSError, HoldoutError) as exc:
        print(f"semantic holdout error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

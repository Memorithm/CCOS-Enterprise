#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-semantic-extraction-holdout.py"
spec = importlib.util.spec_from_file_location("holdout", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def relation(text, subject, rel, polarity, obj):
    raw = text.encode()
    sb = subject.encode()
    ob = obj.encode()
    s = raw.index(sb)
    o = raw.index(ob, s + len(sb))
    return {
        "subject": subject, "relation": rel, "polarity": polarity, "object": obj,
        "subject_span": [s, s + len(sb)], "object_span": [o, o + len(ob)],
    }


def case(i, language, category, text, gold):
    return {
        "id": i, "language": language, "document_family": f"family-{i}",
        "text": text, "content_sha256": sha(text), "categories": [category],
        "annotations": [
            {"reviewer": "reviewer-a", "relations": gold},
            {"reviewer": "reviewer-b", "relations": gold},
        ],
        "gold": gold,
    }


def fixture():
    a = "Alice works at Acme."
    b = "Élodie travaille chez Acme."
    c = "Alice does not work at Beta."
    d = "Alice worked at Acme in 2020."
    e = "Alice is employed by Acme."
    f = "Alice may work at Acme."
    return [
        case("plain-en", "en", "plain", a, [relation(a, "Alice", "works_for", "affirmed", "Acme")]),
        case("plain-fr", "fr", "entity_confusion", b, [relation(b, "Élodie", "works_for", "affirmed", "Acme")]),
        case("neg", "en", "negation", c, [relation(c, "Alice", "works_for", "negated", "Beta")]),
        case("temporal", "en", "temporal", d, []),
        case("paraphrase", "en", "paraphrase", e, [relation(e, "Alice", "works_for", "affirmed", "Acme")]),
        case("abstain", "en", "abstention", f, []),
    ]


def encode(rows):
    return ("\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows) + "\n").encode()


def test_complete_reviewed_holdout_passes_contract():
    report = module.validate_bytes(encode(fixture()))
    assert report["cases"] == 6
    assert report["languages"]["fr"] == 1
    assert set(report["categories"]) == module.REQUIRED_CATEGORIES


def test_single_reviewer_is_refused():
    rows = fixture()
    rows[0]["annotations"] = rows[0]["annotations"][:1]
    try:
        module.validate_bytes(encode(rows))
        raise AssertionError("single-reviewer holdout accepted")
    except module.HoldoutError as exc:
        assert "two independent" in str(exc)


def test_bad_byte_span_is_refused():
    rows = fixture()
    rows[0]["gold"][0]["subject_span"] = [1, 3]
    try:
        module.validate_bytes(encode(rows))
        raise AssertionError("bad span accepted")
    except module.HoldoutError as exc:
        assert "does not match" in str(exc)


def test_missing_challenge_category_is_refused():
    rows = [row for row in fixture() if "temporal" not in row["categories"]]
    try:
        module.validate_bytes(encode(rows))
        raise AssertionError("incomplete category coverage accepted")
    except module.HoldoutError as exc:
        assert "challenge categories" in str(exc)


if __name__ == "__main__":
    tests = [
        test_complete_reviewed_holdout_passes_contract,
        test_single_reviewer_is_refused,
        test_bad_byte_span_is_refused,
        test_missing_challenge_category_is_refused,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} semantic-holdout tests passed")

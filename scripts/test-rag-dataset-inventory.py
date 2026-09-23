#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-rag-dataset-inventory.py"
spec = importlib.util.spec_from_file_location("inventory", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def row(item_id, family, split, byte, authorized=True):
    return {
        "id": item_id,
        "family_id": family,
        "split": split,
        "content_sha256": "sha256:" + byte * 64,
        "license": "authorized-test-fixture",
        "authorized": authorized,
    }


def encode(rows):
    return ("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n").encode()


def valid_rows():
    return [
        row("train-a", "family-a", "train", "a"),
        row("dev-b", "family-b", "dev", "b"),
        row("test-c", "family-c", "test", "c"),
    ]


def test_valid_inventory_reports_disjoint_splits():
    report = module.validate_inventory_bytes(encode(valid_rows()))
    assert report["documents"] == {"dev": 1, "test": 1, "train": 1}
    assert report["family_disjoint"] is True
    assert report["content_hash_disjoint"] is True


def test_family_crossing_splits_is_refused():
    rows = valid_rows()
    rows.append(row("test-a2", "family-a", "test", "d"))
    try:
        module.validate_inventory_bytes(encode(rows))
        raise AssertionError("family leak accepted")
    except module.InventoryError as exc:
        assert "family crosses splits" in str(exc)


def test_exact_content_overlap_is_refused_even_with_new_id():
    rows = valid_rows()
    rows.append(row("test-copy", "family-copy", "test", "a"))
    try:
        module.validate_inventory_bytes(encode(rows))
        raise AssertionError("content leak accepted")
    except module.InventoryError as exc:
        assert "duplicate content hash" in str(exc)


def test_unauthorized_source_is_refused():
    rows = valid_rows()
    rows[2]["authorized"] = False
    try:
        module.validate_inventory_bytes(encode(rows))
        raise AssertionError("unauthorized source accepted")
    except module.InventoryError as exc:
        assert "not authorized" in str(exc)


def test_missing_split_is_refused():
    try:
        module.validate_inventory_bytes(encode(valid_rows()[:2]))
        raise AssertionError("missing test split accepted")
    except module.InventoryError as exc:
        assert "train, dev and test" in str(exc)


if __name__ == "__main__":
    tests = [
        test_valid_inventory_reports_disjoint_splits,
        test_family_crossing_splits_is_refused,
        test_exact_content_overlap_is_refused_even_with_new_id,
        test_unauthorized_source_is_refused,
        test_missing_split_is_refused,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} inventory tests passed")

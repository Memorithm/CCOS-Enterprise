#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-rag-training-overlap-audit.py"
spec = importlib.util.spec_from_file_location("overlap_audit", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def rows():
    def row(i, family, split, byte):
        return {
            "id": i,
            "family_id": family,
            "split": split,
            "content_sha256": "sha256:" + byte * 64,
            "license": "fixture",
            "authorized": True,
        }
    return [
        row("train", "fa", "train", "a"),
        row("dev", "fb", "dev", "b"),
        row("test", "fc", "test", "c"),
    ]


def encoded(items):
    return ("\n".join(json.dumps(x, sort_keys=True) for x in items) + "\n").encode()


def test_audit_is_deterministic_and_passes_clean_inventory():
    first = module.build_audit(encoded(rows()))
    second = module.build_audit(encoded(rows()))
    assert first == second
    assert module.canonical(first) == module.canonical(second)
    assert module.audit_sha256(first) == module.audit_sha256(second)
    assert first["result"] == "pass"
    assert first["content_hash_overlap_count"] == 0
    assert first["document_family_overlap_count"] == 0


def test_inventory_hash_binds_exact_bytes():
    base = encoded(rows())
    audit = module.build_audit(base)
    changed = base + b"\n"
    changed_audit = module.build_audit(changed)
    assert audit["inventory_sha256"] != changed_audit["inventory_sha256"]


def test_overlap_cannot_produce_a_pass_audit():
    bad = rows()
    bad.append({
        "id": "leak",
        "family_id": "fa",
        "split": "test",
        "content_sha256": "sha256:" + "d" * 64,
        "license": "fixture",
        "authorized": True,
    })
    try:
        module.build_audit(encoded(bad))
        raise AssertionError("overlap audit passed leaking family")
    except module.inventory.InventoryError:
        pass


if __name__ == "__main__":
    tests = [
        test_audit_is_deterministic_and_passes_clean_inventory,
        test_inventory_hash_binds_exact_bytes,
        test_overlap_cannot_produce_a_pass_audit,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} overlap-audit tests passed")

#!/usr/bin/env python3
"""Build a canonical training-overlap audit from a validated dataset inventory."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "scripts" / "check-rag-dataset-inventory.py"
spec = importlib.util.spec_from_file_location("rag_inventory", INVENTORY)
inventory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(inventory)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def build_audit(data: bytes) -> dict:
    summary = inventory.validate_inventory_bytes(data)
    return {
        "schema_version": 1,
        "inventory_sha256": summary["inventory_sha256"],
        "policy": {
            "exact_content_hash_overlap_across_splits": "forbidden",
            "document_family_overlap_across_splits": "forbidden",
            "unauthorized_sources": "forbidden",
        },
        "documents": summary["documents"],
        "families": summary["families"],
        "content_hash_overlap_count": 0,
        "document_family_overlap_count": 0,
        "authorized_only": True,
        "result": "pass",
    }


def audit_sha256(audit: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(audit)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        data = inventory.read_bounded(args.inventory)
        audit = build_audit(data)
        encoded = canonical(audit)
        args.output.write_bytes(encoded)
    except (OSError, inventory.InventoryError, ValueError) as exc:
        print(f"overlap audit error: {exc}", file=sys.stderr)
        return 1
    print(audit_sha256(audit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate a document-family-disjoint train/dev/test inventory for a real RAG campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 1_000_000
SPLITS = {"train", "dev", "test"}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class InventoryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "inventory exceeds 64 MiB")
    return data


def clean_label(value: object, name: str, maximum: int = 512) -> str:
    require(isinstance(value, str), f"{name} must be text")
    require(value == value.strip() and 0 < len(value) <= maximum, f"invalid {name}")
    require(not any(ord(ch) < 32 for ch in value), f"invalid {name}")
    return value


def validate_inventory_bytes(data: bytes) -> dict:
    rows = []
    for line_no, raw in enumerate(data.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InventoryError(f"line {line_no}: invalid JSON: {exc}") from exc
        require(isinstance(row, dict), f"line {line_no}: row must be an object")
        require(
            set(row) == {"id", "family_id", "split", "content_sha256", "license", "authorized"},
            f"line {line_no}: unexpected/missing fields",
        )
        rows.append((line_no, row))
        require(len(rows) <= MAX_ROWS, "inventory row ceiling exceeded")

    require(rows, "empty inventory")
    ids: set[str] = set()
    content_owner: dict[str, tuple[str, str]] = {}
    family_split: dict[str, str] = {}
    counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()

    for line_no, row in rows:
        item_id = clean_label(row["id"], f"line {line_no} id")
        family = clean_label(row["family_id"], f"line {line_no} family_id")
        split = clean_label(row["split"], f"line {line_no} split", 16)
        license_name = clean_label(row["license"], f"line {line_no} license", 1024)
        digest = row["content_sha256"]
        require(split in SPLITS, f"line {line_no}: split must be train/dev/test")
        require(type(row["authorized"]) is bool and row["authorized"], f"line {line_no}: source is not authorized")
        require(isinstance(digest, str) and SHA256.fullmatch(digest), f"line {line_no}: invalid content SHA-256")
        require(item_id not in ids, f"line {line_no}: duplicate document id")
        ids.add(item_id)

        prior_content = content_owner.get(digest)
        require(prior_content is None, f"line {line_no}: duplicate content hash already used by {prior_content}" if prior_content else "")
        content_owner[digest] = (item_id, split)

        prior_split = family_split.get(family)
        require(
            prior_split is None or prior_split == split,
            f"line {line_no}: document family crosses splits ({family}: {prior_split} -> {split})",
        )
        family_split[family] = split
        counts[split] += 1
        family_counts[split] += int(prior_split is None)
        _ = license_name

    require(set(counts) == SPLITS, "inventory must contain train, dev and test rows")
    return {
        "schema_version": 1,
        "inventory_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "documents": dict(sorted(counts.items())),
        "families": dict(sorted(family_counts.items())),
        "family_disjoint": True,
        "content_hash_disjoint": True,
        "authorized_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    try:
        summary = validate_inventory_bytes(read_bounded(args.inventory))
    except (OSError, InventoryError) as exc:
        print(f"inventory error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

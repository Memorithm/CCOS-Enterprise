#!/usr/bin/env python3
"""Verify encoder artifact bytes and bind campaign arms to exact embedding spaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HASH = re.compile(r"sha256:[0-9a-f]{64}")
MAX_WEIGHTS_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOKENIZER_BYTES = 64 * 1024 * 1024


class EncoderRegistryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EncoderRegistryError(message)


def clean_label(value, name, maximum=256):
    require(isinstance(value, str) and value == value.strip() and 0 < len(value) <= maximum, f"invalid {name}")
    require(not any(ord(ch) < 32 for ch in value), f"invalid {name}")
    return value


def valid_hash(value, name):
    require(isinstance(value, str) and HASH.fullmatch(value), f"invalid {name}")
    return value


def resolve_file(root: Path, value: str, limit: int) -> Path:
    clean_label(value, "artifact path", 4096)
    path = (root / value).resolve()
    require(path.is_relative_to(root) and path.is_file(), "encoder artifact escapes registry root or is absent")
    require(path.stat().st_size <= limit, "encoder artifact exceeds byte ceiling")
    return path


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def encoder_key(spec: dict) -> tuple:
    return (
        spec["weights_sha256"],
        spec["tokenizer_sha256"],
        spec["pooling"],
        spec["normalization"],
        spec["dimension"],
        spec["query_instruction_sha256"],
        spec["document_instruction_sha256"],
    )


def validate_registry(registry_path: Path) -> dict[tuple, dict]:
    registry_path = registry_path.resolve()
    root = registry_path.parent
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    require(isinstance(data, dict) and set(data) == {"schema_version", "encoders"}, "invalid registry root")
    require(data["schema_version"] == 1 and isinstance(data["encoders"], list) and data["encoders"], "invalid registry version/encoders")
    by_key = {}
    ids = set()
    for row in data["encoders"]:
        require(isinstance(row, dict), "encoder row must be object")
        require(set(row) == {
            "id", "weights_path", "weights_sha256", "tokenizer_path", "tokenizer_sha256",
            "pooling", "normalization", "dimension", "precision", "revision",
            "query_instruction_sha256", "document_instruction_sha256"
        }, "unexpected/missing encoder fields")
        encoder_id = clean_label(row["id"], "encoder id")
        require(encoder_id not in ids, "duplicate encoder id")
        ids.add(encoder_id)
        for name in ("weights_sha256", "tokenizer_sha256", "query_instruction_sha256", "document_instruction_sha256"):
            valid_hash(row[name], name)
        clean_label(row["pooling"], "pooling")
        clean_label(row["normalization"], "normalization")
        clean_label(row["precision"], "precision")
        clean_label(row["revision"], "revision", 1024)
        require(type(row["dimension"]) is int and 1 <= row["dimension"] <= 8192, "invalid encoder dimension")
        weights = resolve_file(root, row["weights_path"], MAX_WEIGHTS_BYTES)
        tokenizer = resolve_file(root, row["tokenizer_path"], MAX_TOKENIZER_BYTES)
        require(hash_file(weights) == row["weights_sha256"], f"{encoder_id}: weights hash mismatch")
        require(hash_file(tokenizer) == row["tokenizer_sha256"], f"{encoder_id}: tokenizer hash mismatch")
        key = encoder_key(row)
        require(key not in by_key, "duplicate embedding space under different encoder rows")
        by_key[key] = row
    return by_key


def validate_campaign(manifest_path: Path, registry_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    registry = validate_registry(registry_path)
    matched = {}
    for arm in manifest.get("arms", []):
        family = arm.get("family")
        if family == "lexical":
            require(arm.get("encoder") is None, "lexical arm cannot use encoder")
            continue
        encoder = arm.get("encoder")
        require(isinstance(encoder, dict), f"{arm.get('id')}: encoder missing")
        key = encoder_key(encoder)
        require(key in registry, f"{arm.get('id')}: encoder artifacts/config are not registered")
        matched[arm["id"]] = registry[key]["id"]
    require(matched, "campaign has no registered non-lexical encoder")
    return {"schema_version": 1, "matched_arms": dict(sorted(matched.items()))}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("registry", type=Path)
    args = parser.parse_args()
    try:
        report = validate_campaign(args.manifest.resolve(), args.registry.resolve())
    except (OSError, json.JSONDecodeError, EncoderRegistryError) as exc:
        print(f"encoder registry error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

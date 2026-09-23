#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-rag-encoder-artifacts.py"
spec = importlib.util.spec_from_file_location("encoders", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encoder_row(weights, tokenizer):
    empty = sha(b"")
    return {
        "id": "compact-v1",
        "weights_path": "weights.bin",
        "weights_sha256": sha(weights),
        "tokenizer_path": "tokenizer.json",
        "tokenizer_sha256": sha(tokenizer),
        "pooling": "mean",
        "normalization": "l2",
        "dimension": 128,
        "precision": "f32",
        "revision": "fixture",
        "query_instruction_sha256": empty,
        "document_instruction_sha256": empty,
    }


def arm_encoder(row):
    return {key: row[key] for key in (
        "weights_sha256", "tokenizer_sha256", "pooling", "normalization", "dimension",
        "query_instruction_sha256", "document_instruction_sha256"
    )}


def fixture():
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    weights = b"weights-v1"
    tokenizer = b'{"type":"fixture"}'
    (root / "weights.bin").write_bytes(weights)
    (root / "tokenizer.json").write_bytes(tokenizer)
    row = encoder_row(weights, tokenizer)
    registry = root / "registry.json"
    registry.write_text(json.dumps({"schema_version": 1, "encoders": [row]}), encoding="utf-8")
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({
        "arms": [
            {"id": "lexical", "family": "lexical", "encoder": None},
            {"id": "dense", "family": "dense", "encoder": arm_encoder(row)},
        ]
    }), encoding="utf-8")
    return tmp, root, row, registry, manifest


def test_real_artifact_hashes_and_campaign_space_match():
    tmp, root, row, registry, manifest = fixture()
    try:
        report = module.validate_campaign(manifest, registry)
        assert report["matched_arms"] == {"dense": "compact-v1"}
    finally:
        tmp.cleanup()


def test_changed_weight_bytes_are_refused():
    tmp, root, row, registry, manifest = fixture()
    try:
        (root / "weights.bin").write_bytes(b"tampered")
        try:
            module.validate_campaign(manifest, registry)
            raise AssertionError("tampered weights accepted")
        except module.EncoderRegistryError as exc:
            assert "weights hash mismatch" in str(exc)
    finally:
        tmp.cleanup()


def test_same_dimension_different_weights_are_not_same_space():
    tmp, root, row, registry, manifest = fixture()
    try:
        data = json.loads(manifest.read_text())
        data["arms"][1]["encoder"]["weights_sha256"] = "sha256:" + "f" * 64
        manifest.write_text(json.dumps(data))
        try:
            module.validate_campaign(manifest, registry)
            raise AssertionError("foreign embedding space accepted")
        except module.EncoderRegistryError as exc:
            assert "not registered" in str(exc)
    finally:
        tmp.cleanup()


def test_artifact_path_escape_is_refused():
    tmp, root, row, registry, manifest = fixture()
    try:
        reg = json.loads(registry.read_text())
        reg["encoders"][0]["weights_path"] = "../outside.bin"
        registry.write_text(json.dumps(reg))
        try:
            module.validate_campaign(manifest, registry)
            raise AssertionError("escaping path accepted")
        except module.EncoderRegistryError:
            pass
    finally:
        tmp.cleanup()


if __name__ == "__main__":
    tests = [
        test_real_artifact_hashes_and_campaign_space_match,
        test_changed_weight_bytes_are_refused,
        test_same_dimension_different_weights_are_not_same_space,
        test_artifact_path_escape_is_refused,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} encoder-artifact tests passed")

#!/usr/bin/env python3
"""Regression tests for the real-campaign readiness gate."""

import copy
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-rag-campaign-readiness.py"
FIXTURE = ROOT / "fixtures" / "rag-campaign-smoke" / "manifest.json"

spec = importlib.util.spec_from_file_location("rag_readiness", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def real_shape():
    manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
    manifest["scope"] = "heldout_enterprise_v1"
    manifest["protocol"]["hardware"].update(
        {"host_id": "thor-aarch64-01", "cpu": "aarch64-14core", "ram_bytes": 131072000000}
    )
    for index, arm in enumerate(manifest["arms"], start=1):
        arm["runner"]["code_sha"] = f"{index:040x}"
        arm["runner"]["command"] = ["runner", "--arm", arm["id"]]
        arm["runner"]["index_config"] = {"frozen": True}
        arm["measurement"].update(
            {"wall_seconds": 1.0 + index, "restart_ms": index, "peak_rss_bytes": 1024 * index, "cost_microunits": index}
        )
    return manifest


def test_smoke_fixture_is_refused():
    smoke = json.loads(FIXTURE.read_text(encoding="utf-8"))
    errors = module.check_manifest(smoke)
    assert errors
    assert any("synthetic" in error for error in errors)


def test_real_shape_passes_readiness_structure():
    assert module.check_manifest(real_shape()) == []


def test_zero_runner_sha_is_refused():
    manifest = real_shape()
    manifest["arms"][0]["runner"]["code_sha"] = "0" * 40
    assert any("code_sha" in error for error in module.check_manifest(manifest))


def test_primary_baseline_comparison_is_mandatory():
    manifest = real_shape()
    manifest["comparisons"] = [
        row for row in manifest["comparisons"] if row["baseline"] != manifest["decision_rule"]["primary_baseline"]
    ]
    assert any("primary baseline" in error for error in module.check_manifest(manifest))


def test_missing_dataset_provenance_is_refused():
    manifest = real_shape()
    del manifest["dataset_provenance"]["license"]
    assert any("dataset_provenance.license" in error for error in module.check_manifest(manifest))


if __name__ == "__main__":
    tests = [
        test_smoke_fixture_is_refused,
        test_real_shape_passes_readiness_structure,
        test_zero_runner_sha_is_refused,
        test_primary_baseline_comparison_is_mandatory,
        test_missing_dataset_provenance_is_refused,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} readiness tests passed")

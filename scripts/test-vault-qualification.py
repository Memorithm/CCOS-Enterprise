#!/usr/bin/env python3
"""Regression tests for the Vault qualification evidence verifier."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_vault_qualification", ROOT / "scripts" / "verify-vault-qualification.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def active(checks: dict[str, bool] | None = None) -> dict:
    return {
        "schema": "ccos-vault-qualification-active.v1",
        "vault_version": "2.1.2",
        "vault_address_class": "http_loopback_ephemeral",
        "transit_key_type": "aes256-gcm96-derived",
        "checks": checks or {key: True for key in MODULE.ACTIVE_CHECKS},
        "limits": ["single node", "loopback HTTP", "no HSM"],
    }


def outage() -> dict:
    return {
        "schema": "ccos-vault-qualification-outage.v1",
        "checks": {key: True for key in MODULE.OUTAGE_CHECKS},
    }


with tempfile.TemporaryDirectory(prefix="ccos-vault-evidence-") as raw:
    root = Path(raw)
    active_path = root / "active.json"
    outage_path = root / "outage.json"
    output_path = root / "combined.json"
    active_path.write_text(json.dumps(active()), encoding="utf-8")
    outage_path.write_text(json.dumps(outage()), encoding="utf-8")
    result = MODULE.combine(
        active_path,
        outage_path,
        output_path,
        expected_version="2.1.2",
        expected_binary_sha256="a" * 64,
        commit_sha="b" * 40,
        run_id="123",
    )
    assert result["status"] == "passed"
    assert set(result["checks"]) == MODULE.ACTIVE_CHECKS | MODULE.OUTAGE_CHECKS
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == "passed"

    broken = active()
    broken["checks"]["renewable_token_renewed"] = False
    active_path.write_text(json.dumps(broken), encoding="utf-8")
    try:
        MODULE.combine(
            active_path,
            outage_path,
            output_path,
            expected_version="2.1.2",
            expected_binary_sha256="a" * 64,
            commit_sha="b" * 40,
            run_id="123",
        )
    except ValueError as error:
        assert "not true" in str(error)
    else:
        raise AssertionError("a false qualification result must fail closed")

    leaked = active()
    leaked["token"] = "must-not-be-recorded"
    active_path.write_text(json.dumps(leaked), encoding="utf-8")
    try:
        MODULE.combine(
            active_path,
            outage_path,
            output_path,
            expected_version="2.1.2",
            expected_binary_sha256="a" * 64,
            commit_sha="b" * 40,
            run_id="123",
        )
    except ValueError as error:
        assert "forbidden evidence field" in str(error)
    else:
        raise AssertionError("secret-like fields must be rejected")

print("Vault qualification evidence verifier: 3/3 passed")

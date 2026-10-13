#!/usr/bin/env python3
"""Validate and combine secret-free evidence from the real-Vault CI campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVE_CHECKS = {
    "real_vault_health",
    "least_privilege_named_key_acl",
    "cross_key_encrypt_denied",
    "service_key_rotation_denied",
    "renewable_token_renewed",
    "nonrenewable_token_expired_fail_closed",
    "transit_rotation_to_v2",
    "old_backup_restored_before_retirement",
    "backup_rewrapped_and_restored_after_rotation",
    "v1_refused_after_min_decryption_version_2",
    "v2_restored_after_retirement",
}
OUTAGE_CHECKS = {"stopped_real_vault_fails_closed"}
FORBIDDEN_KEYS = {"token", "root_token", "client_token", "secret", "plaintext", "private_key"}


def load_object(path: Path, limit: int = 128 * 1024) -> tuple[dict[str, Any], str]:
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise ValueError(f"{path} is empty or exceeds {limit} bytes")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value, hashlib.sha256(data).hexdigest()


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden evidence field {path}.{key}")
            reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{path}[{index}]")


def exact_true_checks(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} check set differs from the qualification contract")
    failed = sorted(key for key, result in value.items() if result is not True)
    if failed:
        raise ValueError(f"{label} checks are not true: {', '.join(failed)}")


def combine(
    active_path: Path,
    outage_path: Path,
    output_path: Path,
    *,
    expected_version: str,
    expected_binary_sha256: str,
    commit_sha: str,
    run_id: str,
) -> dict[str, Any]:
    active, active_sha256 = load_object(active_path)
    outage, outage_sha256 = load_object(outage_path)
    reject_secret_fields(active)
    reject_secret_fields(outage)
    if active.get("schema") != "ccos-vault-qualification-active.v1":
        raise ValueError("unexpected active evidence schema")
    if outage.get("schema") != "ccos-vault-qualification-outage.v1":
        raise ValueError("unexpected outage evidence schema")
    if active.get("vault_version") != expected_version:
        raise ValueError("Vault version differs from the pinned workflow version")
    if active.get("vault_address_class") != "http_loopback_ephemeral":
        raise ValueError("qualification server was not classified as loopback ephemeral")
    if active.get("transit_key_type") != "aes256-gcm96-derived":
        raise ValueError("unexpected Transit key type")
    exact_true_checks(active.get("checks"), ACTIVE_CHECKS, "active")
    exact_true_checks(outage.get("checks"), OUTAGE_CHECKS, "outage")
    limits = active.get("limits")
    if not isinstance(limits, list) or len(limits) < 3 or not all(
        isinstance(item, str) and item for item in limits
    ):
        raise ValueError("qualification limits must be explicit")
    if len(expected_binary_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in expected_binary_sha256
    ):
        raise ValueError("binary SHA-256 must be lowercase hexadecimal")
    if len(commit_sha) != 40 or any(char not in "0123456789abcdef" for char in commit_sha):
        raise ValueError("commit SHA must be lowercase hexadecimal")
    if not run_id.isdecimal():
        raise ValueError("GitHub run id must be numeric")

    result = {
        "schema": "ccos-vault-qualification.v1",
        "status": "passed",
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "repository": "Memorithm/CCOS-Enterprise",
            "commit_sha": commit_sha,
            "github_run_id": run_id,
        },
        "vault": {
            "version": expected_version,
            "binary_sha256": expected_binary_sha256,
            "mode": "ephemeral_single_node_dev",
            "address_class": "http_loopback_only",
        },
        "evidence_inputs": {
            "active_sha256": active_sha256,
            "outage_sha256": outage_sha256,
        },
        "checks": {**active["checks"], **outage["checks"]},
        "limits": limits
        + [
            "the run-local Ed25519 signature proves evidence-file consistency only",
            "GitHub run identity and logs remain the qualification authority",
        ],
    }
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--active", type=Path, required=True)
    parser.add_argument("--outage", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vault-version", required=True)
    parser.add_argument("--vault-binary-sha256", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    combine(
        args.active,
        args.outage,
        args.output,
        expected_version=args.vault_version,
        expected_binary_sha256=args.vault_binary_sha256,
        commit_sha=args.commit_sha,
        run_id=args.run_id,
    )
    print(f"Vault qualification evidence validated: {args.output}")


if __name__ == "__main__":
    main()

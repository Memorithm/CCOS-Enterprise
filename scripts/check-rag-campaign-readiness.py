#!/usr/bin/env python3
"""Fail-closed readiness gate for a *real* CCOS/RAG campaign manifest.

The comparative scorer deliberately accepts the repository's synthetic smoke
fixture because it tests evaluator mechanics. This separate gate is for campaign
execution: it rejects synthetic placeholders before a run can be represented as
real experimental evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FAMILIES = {"governed_memory", "lexical", "dense", "hybrid", "reranked"}
ZERO_SHA = "0" * 40


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def check_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []

    scope = str(manifest.get("scope", "")).strip()
    lowered_scope = scope.lower()
    require(bool(scope), "scope is required", errors)
    require(
        "synthetic" not in lowered_scope and "smoke" not in lowered_scope,
        "synthetic/smoke scope is not a real campaign",
        errors,
    )

    provenance = manifest.get("dataset_provenance") or {}
    for key in ("origin", "license", "split_author", "training_overlap_audit_sha256"):
        require(bool(str(provenance.get(key, "")).strip()), f"dataset_provenance.{key} is required", errors)

    protocol = manifest.get("protocol") or {}
    hardware = protocol.get("hardware") or {}
    host_id = str(hardware.get("host_id", "")).strip()
    cpu = str(hardware.get("cpu", "")).strip()
    require(bool(host_id), "protocol.hardware.host_id is required", errors)
    require(host_id != "synthetic-unexecuted", "synthetic hardware host_id is forbidden", errors)
    require(bool(cpu) and cpu.lower() != "synthetic", "real CPU identity is required", errors)
    require(int(hardware.get("ram_bytes", 0) or 0) > 0, "hardware RAM must be measured", errors)

    arms = manifest.get("arms")
    require(isinstance(arms, list) and bool(arms), "arms must be a non-empty list", errors)
    arms = arms if isinstance(arms, list) else []
    families = {arm.get("family") for arm in arms if isinstance(arm, dict)}
    require(families == FAMILIES, "all five reference families are required", errors)

    ids: set[str] = set()
    for arm in arms:
        if not isinstance(arm, dict):
            errors.append("every arm must be an object")
            continue
        arm_id = str(arm.get("id", "")).strip()
        require(bool(arm_id), "every arm requires an id", errors)
        require(arm_id not in ids, f"duplicate arm id: {arm_id}", errors)
        ids.add(arm_id)

        runner = arm.get("runner") or {}
        code_sha = str(runner.get("code_sha", "")).strip().lower()
        command = runner.get("command")
        require(len(code_sha) == 40 and code_sha != ZERO_SHA, f"{arm_id}: real runner code_sha required", errors)
        require(
            isinstance(command, list)
            and bool(command)
            and all(isinstance(part, str) and part.strip() for part in command),
            f"{arm_id}: non-empty runner command required",
            errors,
        )
        if isinstance(command, list):
            joined = " ".join(str(part) for part in command).lower()
            require("synthetic" not in joined and "no-runner" not in joined, f"{arm_id}: synthetic runner forbidden", errors)

        measurement = arm.get("measurement") or {}
        require(float(measurement.get("wall_seconds", 0) or 0) > 0, f"{arm_id}: wall_seconds must be measured", errors)
        require(int(measurement.get("peak_rss_bytes", 0) or 0) > 0, f"{arm_id}: peak_rss_bytes must be measured", errors)
        require(int(measurement.get("restart_ms", -1)) >= 0, f"{arm_id}: restart_ms is required", errors)
        require(int(measurement.get("cost_microunits", -1)) >= 0, f"{arm_id}: cost_microunits is required", errors)

        results = arm.get("results") or {}
        require(bool(results.get("path")), f"{arm_id}: results.path is required", errors)
        require(bool(results.get("sha256")), f"{arm_id}: results.sha256 is required", errors)

    decision = manifest.get("decision_rule") or {}
    primary = str(decision.get("primary_baseline", "")).strip()
    require(bool(primary), "decision_rule.primary_baseline is required", errors)
    require(primary in ids, "primary baseline must name an arm", errors)
    require(
        any(
            isinstance(c, dict)
            and c.get("candidate") == "ccos"
            and c.get("baseline") == primary
            for c in (manifest.get("comparisons") or [])
        ),
        "comparison against the preregistered primary baseline is required",
        errors,
    )

    judgments = manifest.get("judgments") or {}
    require(bool(judgments.get("path")), "judgments.path is required", errors)
    require(bool(judgments.get("sha256")), "judgments.sha256 is required", errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--overlap-audit", type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"readiness error: {exc}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("readiness error: manifest root must be an object", file=sys.stderr)
        return 2

    errors = check_manifest(manifest)
    if "synthetic" not in str(manifest.get("scope", "")).lower() and "smoke" not in str(manifest.get("scope", "")).lower():
        if args.overlap_audit is None:
            errors.append("real campaign requires --overlap-audit")
        else:
            errors.extend(verify_overlap_audit(manifest, args.overlap_audit))
    if errors:
        for error in errors:
            print(f"readiness error: {error}", file=sys.stderr)
        return 1

    print(json.dumps({"ready": True, "scope": manifest["scope"], "arms": len(manifest["arms"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

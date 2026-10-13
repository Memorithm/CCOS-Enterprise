#!/usr/bin/env python3
"""Fail-closed verifier and selective sync helper for the embedded CCOS Core.

The committed manifest is authoritative. Network access is never implicit:
`audit` and `sync` require an already checked-out upstream repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "core" / "UPSTREAM_CCOS_CORE.json"


class SyncError(RuntimeError):
    pass


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SyncError(f"cannot read lineage manifest {path}: {exc}") from exc
    if manifest.get("schema_version") != 1:
        raise SyncError("unsupported lineage manifest schema")
    if manifest.get("sync_mode") != "reviewed-slices":
        raise SyncError("lineage manifest must fail closed to reviewed-slices mode")
    return manifest


def core_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise SyncError(f"unsafe Core path in manifest: {relative!r}")
    resolved = root / "core" / candidate
    if resolved.is_symlink():
        raise SyncError(f"refusing symlinked vendored file: {relative}")
    return resolved


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_local(root: Path, manifest: dict[str, Any]) -> None:
    exact = manifest.get("exact_files")
    if not isinstance(exact, dict) or not exact:
        raise SyncError("lineage manifest has no exact_files")
    for relative, expected in sorted(exact.items()):
        path = core_path(root, relative)
        try:
            actual = digest(path.read_bytes())
        except OSError as exc:
            raise SyncError(f"cannot read vendored file {relative}: {exc}") from exc
        if actual != expected:
            raise SyncError(
                f"vendored file {relative} has {actual}, expected {expected}"
            )

    overlays = manifest.get("enterprise_overlays")
    if not isinstance(overlays, dict) or not overlays:
        raise SyncError("lineage manifest has no enterprise_overlays")
    for relative, markers in sorted(overlays.items()):
        path = root / "core" / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SyncError(f"cannot read overlay {relative}: {exc}") from exc
        for marker in markers:
            if marker not in text:
                raise SyncError(f"overlay {relative} is missing marker {marker!r}")

    changed = manifest.get("security_diff", {}).get("changed_paths")
    dispositions = manifest.get("security_diff", {}).get("dispositions")
    if not isinstance(changed, list) or not isinstance(dispositions, dict):
        raise SyncError("security diff inventory is missing")
    classified = [path for paths in dispositions.values() if isinstance(paths, list) for path in paths]
    if len(classified) != len(set(classified)):
        raise SyncError("security diff path has more than one disposition")
    if set(changed) != set(classified):
        missing = sorted(set(changed) - set(classified))
        extra = sorted(set(classified) - set(changed))
        raise SyncError(f"security diff disposition mismatch: missing={missing}, extra={extra}")


def git(upstream: Path, *args: str, binary: bool = False) -> bytes | str:
    command = ["git", "-C", str(upstream), *args]
    try:
        result = subprocess.run(command, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode("utf-8", "replace").strip()
        raise SyncError(f"git command failed: {' '.join(command)}: {detail}") from exc
    if binary:
        return result.stdout
    return result.stdout.decode("utf-8").strip()


def audit_upstream(upstream: Path, manifest: dict[str, Any]) -> None:
    reviewed = manifest["reviewed_upstream"]
    commit = reviewed["commit"]
    actual_commit = git(upstream, "rev-parse", f"{commit}^{{commit}}")
    actual_tree = git(upstream, "rev-parse", f"{commit}^{{tree}}")
    if actual_commit != commit or actual_tree != reviewed["tree"]:
        raise SyncError(
            f"upstream identity mismatch: commit={actual_commit}, tree={actual_tree}"
        )

    security = manifest["security_diff"]
    actual_paths = str(git(upstream, "diff", "--name-only", security["range"])).splitlines()
    if sorted(actual_paths) != sorted(security["changed_paths"]):
        raise SyncError("recorded security diff does not match the reviewed Git range")

    for relative, expected in sorted(manifest["exact_files"].items()):
        upstream_data = git(upstream, "show", f"{commit}:{relative}", binary=True)
        assert isinstance(upstream_data, bytes)
        if digest(upstream_data) != expected:
            raise SyncError(f"upstream {relative} does not match the recorded digest")


def sync_files(root: Path, upstream: Path, manifest: dict[str, Any], apply: bool) -> None:
    audit_upstream(upstream, manifest)
    commit = manifest["reviewed_upstream"]["commit"]
    for relative in sorted(manifest["exact_files"]):
        source = git(upstream, "show", f"{commit}:{relative}", binary=True)
        assert isinstance(source, bytes)
        destination = core_path(root, relative)
        current = destination.read_bytes() if destination.exists() else None
        if current == source:
            continue
        if not apply:
            raise SyncError(f"{relative} differs; rerun sync with --apply after review")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        shutil.copymode(destination, temporary) if destination.exists() else os.chmod(temporary, 0o644)
        os.replace(temporary, destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify")
    for command in ("audit", "sync"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--upstream", required=True, type=Path)
        if command == "sync":
            sub.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest()
        verify_local(ROOT, manifest)
        if args.command == "audit":
            audit_upstream(args.upstream, manifest)
        elif args.command == "sync":
            sync_files(ROOT, args.upstream, manifest, args.apply)
            verify_local(ROOT, manifest)
    except SyncError as exc:
        print(f"core-sync: {exc}", file=sys.stderr)
        return 1
    print(f"core-sync: {args.command} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

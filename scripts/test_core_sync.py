#!/usr/bin/env python3

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("core_sync.py")
SPEC = importlib.util.spec_from_file_location("core_sync", SCRIPT)
assert SPEC and SPEC.loader
core_sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core_sync)


class CoreSyncTests(unittest.TestCase):
    def test_repository_manifest_verifies(self):
        manifest = core_sync.load_manifest()
        core_sync.verify_local(core_sync.ROOT, manifest)

    def test_exact_file_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "core").mkdir()
            (root / "core" / "payload.rs").write_text("tampered", encoding="utf-8")
            manifest = {
                "exact_files": {"payload.rs": core_sync.digest(b"expected")},
                "enterprise_overlays": {"payload.rs": ["tampered"]},
                "security_diff": {
                    "changed_paths": ["payload.rs"],
                    "dispositions": {"imported_exact": ["payload.rs"]},
                },
            }
            with self.assertRaises(core_sync.SyncError):
                core_sync.verify_local(root, manifest)

    def test_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(core_sync.SyncError):
                core_sync.core_path(Path(directory), "../Cargo.toml")

    def test_unclassified_security_path_is_rejected(self):
        manifest = copy.deepcopy(core_sync.load_manifest())
        manifest["security_diff"]["changed_paths"].append("unreviewed.rs")
        with self.assertRaises(core_sync.SyncError):
            core_sync.verify_local(core_sync.ROOT, manifest)

    def test_security_range_must_bind_recorded_anchors(self):
        manifest = copy.deepcopy(core_sync.load_manifest())
        core_sync.validate_anchor_relationships(manifest)
        manifest["security_diff"]["range"] = (
            "0000000000000000000000000000000000000000.."
            + manifest["reviewed_upstream"]["commit"]
        )
        with self.assertRaises(core_sync.SyncError):
            core_sync.validate_anchor_relationships(manifest)


if __name__ == "__main__":
    unittest.main()

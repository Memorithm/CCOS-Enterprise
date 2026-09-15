#!/usr/bin/env python3
"""Regression tests for CI control flow; no Rust installation or network needed."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

GUARDS = Path(__file__).resolve().with_name("ci-guards.sh")


class Guards(unittest.TestCase):
    def run_guard(self, function, *arguments, conditional=False, env=None):
        # Even an `if` caller must not disable the checks inside the functions.
        script = 'source "$1"; shift; "$@"'
        if conditional:
            script = 'source "$1"; shift; if "$@"; then exit 0; else exit $?; fi'
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script, "guard", str(GUARDS),
             function, *arguments],
            text=True, capture_output=True, timeout=10, env=env,
        )

    def output(self, code, pattern="forbidden", **kwargs):
        return self.run_guard("require_clean_output", pattern, sys.executable,
                              "-c", code, **kwargs)

    def test_clean_nonempty_output(self):
        self.assertEqual(self.output('print("allowed")').returncode, 0)

    def test_forbidden_output(self):
        self.assertEqual(self.output('print("FORBIDDEN")').returncode, 1)

    def test_empty_success_is_not_evidence(self):
        self.assertEqual(self.output("pass").returncode, 2)

    def test_failed_producer_without_output(self):
        result = self.output("raise SystemExit(17)")
        self.assertEqual(result.returncode, 17)
        self.assertIn("producer failed", result.stderr)

    def test_failed_producer_with_clean_partial_output(self):
        result = self.output('print("allowed"); raise SystemExit(17)')
        self.assertEqual(result.returncode, 17)

    def test_failed_producer_preserves_stderr(self):
        result = self.output('import sys; print("diagnostic", file=sys.stderr); sys.exit(17)')
        self.assertEqual(result.returncode, 17)
        self.assertIn("diagnostic", result.stderr)

    def test_invalid_pattern_is_not_no_match(self):
        self.assertEqual(self.output('print("allowed")', pattern="[").returncode, 2)

    def test_missing_producer(self):
        result = self.run_guard("require_clean_output", "forbidden", "/no/such/producer")
        self.assertEqual(result.returncode, 127)

    def test_missing_scanner_input(self):
        result = self.run_guard("require_no_matches", "grep", "x", "/no/such/input")
        self.assertEqual(result.returncode, 2)

    def test_scanner_exit_codes(self):
        for status, expected in [(0, 1), (1, 0), (2, 2), (17, 17)]:
            with self.subTest(status=status):
                result = self.run_guard("require_no_matches", sys.executable,
                                        "-c", f"raise SystemExit({status})")
                self.assertEqual(result.returncode, expected)

    def test_conditional_callers_cannot_mask_failures(self):
        for code, expected in [('print("allowed")', 0), ("raise SystemExit(17)", 17),
                               ('print("forbidden")', 1), ("pass", 2)]:
            with self.subTest(code=code):
                self.assertEqual(self.output(code, conditional=True).returncode, expected)

    def test_arguments_are_not_reparsed_as_shell(self):
        result = self.run_guard("require_clean_output", "forbidden", sys.executable,
                               "-c", 'import sys; assert sys.argv[1] == "a b; exit 99"; print("ok")',
                               "a b; exit 99")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_temporary_files_are_cleaned_after_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, TMPDIR=tmp)
            for code in ['print("allowed")', 'print("forbidden")', "raise SystemExit(17)"]:
                self.output(code, env=env)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_whole_large_output_is_checked_without_early_pipe_close(self):
        result = self.output('print("allowed\\n" * 100000); print("forbidden")')
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

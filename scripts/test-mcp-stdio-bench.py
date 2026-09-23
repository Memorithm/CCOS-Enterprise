#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench-mcp-stdio.py"
spec = importlib.util.spec_from_file_location("bench", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

ECHO = r"""
import json, sys
for line in sys.stdin:
    request=json.loads(line)
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":{"ok":True}}, separators=(",",":")), flush=True)
"""

WRONG = r"""
import json, sys
for line in sys.stdin:
    request=json.loads(line)
    print(json.dumps({"jsonrpc":"2.0","id":"wrong","result":{}}, separators=(",",":")), flush=True)
"""


def requests():
    return [
        (1, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'),
        (2, b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'),
    ]


def test_success_records_every_request_and_restart_probe():
    report = module.run_benchmark([sys.executable, "-u", "-c", ECHO], requests(), 2, 5)
    assert report["failures"] == []
    assert report["samples"] == 4
    assert len(report["latency_ns"]) == 4
    assert report["p50_ns"] > 0
    assert report["p95_ns"] >= report["p50_ns"]
    assert all(row["completed"] == 2 for row in report["repetitions"])
    assert all(row["process_start_to_first_response_ms"] is not None for row in report["repetitions"])


def test_response_id_mismatch_is_preserved_as_failure():
    report = module.run_benchmark([sys.executable, "-u", "-c", WRONG], requests(), 1, 5)
    assert report["failures"]
    assert report["repetitions"][0]["completed"] == 0


def test_request_loader_refuses_duplicate_ids():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "requests.jsonl"
        path.write_text('{"id":1}\n{"id":1}\n')
        try:
            module.load_requests(path)
            raise AssertionError("duplicate request id accepted")
        except module.BenchError:
            pass


def test_command_loader_requires_array_without_shell_parsing():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "command.json"
        path.write_text(json.dumps([sys.executable, "-u", "-c", ECHO]))
        command, digest = module.load_command(path)
        assert command[0] == sys.executable
        assert digest.startswith("sha256:")
        path.write_text(json.dumps("python -c evil"))
        try:
            module.load_command(path)
            raise AssertionError("shell command string accepted")
        except module.BenchError:
            pass


if __name__ == "__main__":
    tests = [
        test_success_records_every_request_and_restart_probe,
        test_response_id_mismatch_is_preserved_as_failure,
        test_request_loader_refuses_duplicate_ids,
        test_command_loader_requires_array_without_shell_parsing,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} stdio-benchmark tests passed")

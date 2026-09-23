#!/usr/bin/env python3
"""Measure a pre-provisioned JSON-RPC stdio server without shell re-parsing.

This harness includes process launch, stdio framing and response parsing. It does
not provision CCOS state, create credentials, encode text, or run a generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024
MAX_REQUESTS = 100_000
MAX_REPETITIONS = 100
MAX_RESPONSE = 64 * 1024 * 1024


class BenchError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchError(message)


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    require(len(data) <= MAX_FILE, "input file exceeds 64 MiB")
    return data


def load_command(path: Path) -> tuple[list[str], str]:
    raw = bounded(path)
    value = json.loads(raw)
    require(
        isinstance(value, list)
        and 1 <= len(value) <= 256
        and all(isinstance(part, str) and part and "\x00" not in part for part in value),
        "command JSON must be a non-empty array of strings",
    )
    return value, sha256(raw)


def load_requests(path: Path) -> tuple[list[tuple[object, bytes]], str]:
    raw = bounded(path)
    requests = []
    ids = set()
    for line_no, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        require(isinstance(value, dict) and "id" in value, f"line {line_no}: JSON-RPC object with id required")
        request_id = value["id"]
        key = json.dumps(request_id, sort_keys=True)
        require(key not in ids, f"line {line_no}: duplicate request id")
        ids.add(key)
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        requests.append((request_id, encoded))
        require(len(requests) <= MAX_REQUESTS, "request count ceiling exceeded")
    require(requests, "request file is empty")
    return requests, sha256(raw)


def percentile(values: list[int], percent: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def rss_kib(pid: int) -> tuple[int | None, int | None]:
    path = Path(f"/proc/{pid}/status")
    try:
        fields = {}
        for line in path.read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                name, value, unit = line.split()
                if unit == "kB":
                    fields[name.rstrip(":")] = int(value)
        return fields.get("VmRSS"), fields.get("VmHWM")
    except (OSError, ValueError):
        return None, None


def read_line_with_timeout(process: subprocess.Popen, timeout: float) -> bytes:
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(timeout), "server response timeout")
        line = process.stdout.readline(MAX_RESPONSE + 1)
    finally:
        selector.close()
    require(line, "server closed stdout before response")
    require(len(line) <= MAX_RESPONSE, "server response exceeds 64 MiB")
    return line


def stop_process(process: subprocess.Popen) -> int:
    if process.stdin:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        return process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            return process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=2)


def run_benchmark(command: list[str], requests, repetitions: int, timeout: float) -> dict:
    require(1 <= repetitions <= MAX_REPETITIONS, "invalid repetitions")
    require(0 < timeout <= 300, "invalid response timeout")
    samples = []
    repetition_rows = []
    failures = []
    max_rss = 0
    max_hwm = 0
    total_start = time.perf_counter_ns()

    for repetition in range(repetitions):
        with tempfile.TemporaryFile() as stderr_file:
            spawn_start = time.perf_counter_ns()
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                shell=False,
                bufsize=0,
            )
            first_response_ms = None
            completed = 0
            try:
                assert process.stdin is not None
                for request_id, encoded in requests:
                    started = time.perf_counter_ns()
                    process.stdin.write(encoded)
                    process.stdin.flush()
                    try:
                        line = read_line_with_timeout(process, timeout)
                        response = json.loads(line)
                        require(isinstance(response, dict), "server response must be JSON object")
                        require(response.get("id") == request_id, "JSON-RPC response id mismatch")
                        if "error" in response:
                            failures.append({
                                "repetition": repetition,
                                "request_id": request_id,
                                "kind": "jsonrpc_error",
                            })
                        completed += 1
                    except (BenchError, json.JSONDecodeError, OSError) as exc:
                        failures.append({
                            "repetition": repetition,
                            "request_id": request_id,
                            "kind": str(exc),
                        })
                        break
                    finally:
                        elapsed = time.perf_counter_ns() - started
                        samples.append(elapsed)
                        if first_response_ms is None:
                            first_response_ms = (time.perf_counter_ns() - spawn_start) / 1_000_000
                        rss, hwm = rss_kib(process.pid)
                        if rss is not None:
                            max_rss = max(max_rss, rss)
                        if hwm is not None:
                            max_hwm = max(max_hwm, hwm)
            finally:
                exit_code = stop_process(process)
                stderr_file.seek(0)
                stderr_digest = sha256(stderr_file.read())
            repetition_rows.append({
                "repetition": repetition,
                "completed": completed,
                "process_start_to_first_response_ms": first_response_ms,
                "exit_code": exit_code,
                "stderr_sha256": stderr_digest,
            })

    wall_ns = time.perf_counter_ns() - total_start
    return {
        "schema_version": 1,
        "scope": "stdio_process_and_jsonrpc_framing_only",
        "samples": len(samples),
        "latency_ns": samples,
        "p50_ns": percentile(samples, 50),
        "p95_ns": percentile(samples, 95),
        "p99_ns": percentile(samples, 99),
        "wall_seconds": wall_ns / 1_000_000_000,
        "throughput_requests_per_second": (sum(r["completed"] for r in repetition_rows) / (wall_ns / 1_000_000_000)) if wall_ns else None,
        "max_vm_rss_kib": max_rss or None,
        "max_vm_hwm_kib": max_hwm or None,
        "repetitions": repetition_rows,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--command-json", required=True, type=Path)
    parser.add_argument("--requests", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    try:
        command, command_hash = load_command(args.command_json)
        requests, request_hash = load_requests(args.requests)
        report = run_benchmark(command, requests, args.repetitions, args.timeout_seconds)
        report["command_json_sha256"] = command_hash
        report["requests_sha256"] = request_hash
        args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, json.JSONDecodeError, BenchError, ValueError) as exc:
        print(f"stdio benchmark error: {exc}", file=sys.stderr)
        return 2
    return 1 if report["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

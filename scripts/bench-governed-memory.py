#!/usr/bin/env python3
"""A09: isolated processes, full distributions, recovery equality and honest failures."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def command(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def quantiles(values):
    ordered = sorted(values)
    return {f"p{p}_ms": ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)] / 1e6
            for p in (50, 95, 99)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--tenants", default="1,4")
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/examples/governed_memory_bench")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    report = {"schema_version": 1, "git_sha": command(["git", "rev-parse", "HEAD"]),
              "dirty": bool(command(["git", "status", "--porcelain"])),
              "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "platform": platform.platform(), "machine": platform.machine(),
              "rustc": command(["rustc", "--version"]),
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
              "profile": {"dimension": 32, "payload_bytes": 64, "simhash_bits": 64, "seed": 20260919,
                          "trust_policy": "AnyNonQuarantined", "synthetic": True,
                          "k": 8, "shortlist": 64, "context_bytes": 4096,
                          "samples_per_tenant": args.samples, "repetitions": args.repetitions},
              "scope": "signed identity; shared Deployment::admit; governed adapter; bound context; attestation",
              "limitations": ["no MCP transport or generator measured", "not a quality benchmark",
                              "normal process restart, not power loss", "OS page cache is not flushed",
                              "RSS is process-wide Linux VmRSS/VmHWM; null elsewhere",
                              "nearest-rank empirical quantiles, no inferred SLO"], "cases": []}
    failures = 0
    for size in map(int, args.sizes.split(",")):
        for tenants in map(int, args.tenants.split(",")):
            for repetition in range(args.repetitions):
                case = {"assets_per_tenant": size, "tenants": tenants, "repetition": repetition, "phases": []}
                report["cases"].append(case)
                with tempfile.TemporaryDirectory(prefix="ccos-a09-") as directory:
                    for phase in ("init", "query", "query"):
                        cmd = [str(binary), phase, directory, str(size), str(tenants), str(args.samples)]
                        try:
                            result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=args.timeout)
                            if result.returncode:
                                raise RuntimeError(f"exit={result.returncode}: {result.stderr[-4000:]}")
                            data = json.loads(result.stdout)
                            if phase == "query":
                                ns = [n for worker in data["workers"] for n in worker["latency_ns"]]
                                data["latency"] = quantiles(ns)
                                data["throughput_requests_s"] = len(ns) * 1e9 / data["query_wall_ns"]
                                for worker in data["workers"]:
                                    worker["latency"] = quantiles(worker["latency_ns"])
                            case["phases"].append(data)
                        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                            case.update(status="failed", error=str(error))
                            failures += 1
                            break
                    else:
                        before, after = case["phases"][1:]
                        same = all((x["result_sha256"], x["image_sha256"]) == (y["result_sha256"], y["image_sha256"])
                                   for x, y in zip(before["workers"], after["workers"], strict=True))
                        case["status"] = "passed" if same else "recovery_mismatch"
                        failures += not same
                    case["generation_bytes"] = sum(p.stat().st_size for p in Path(directory).rglob("*") if p.is_file())
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps({k: case[k] for k in ("assets_per_tenant", "tenants", "repetition", "status")}), flush=True)
    # Capacity refusals and timeouts remain failures, never synthetic successes.
    return int(failures > 0)


if __name__ == "__main__":
    raise SystemExit(main())

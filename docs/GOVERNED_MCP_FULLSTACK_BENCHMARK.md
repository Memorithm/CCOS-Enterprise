# Full-stack stdio benchmark harness

`scripts/bench-mcp-stdio.py` measures a pre-provisioned JSON-RPC stdio server as
an external process. Unlike A09's in-process governed-memory measurements, the
timed interval includes request serialization already present in the JSONL
fixture, pipe I/O, server JSON-RPC framing, dispatch and response parsing.

The harness deliberately does **not** provision CCOS, create credentials, encode
source text or run an LLM. Those remain separate costs until a real campaign
supplies them. `process_start_to_first_response_ms` is a launch-plus-first-call
measurement, not a pure server startup time. No samples are discarded as warmup.

Command arguments are supplied as a JSON array and passed with `shell=False`.
Request IDs must be unique. Every JSON-RPC error, timeout, malformed response or
ID mismatch remains in the report and makes the command exit nonzero. Raw latency
samples are preserved; p50/p95/p99 use nearest-rank quantiles. Linux VmRSS/VmHWM
are sampled when `/proc` is available.

Example:

```sh
python3 scripts/bench-mcp-stdio.py \
  --command-json /path/to/frozen-server-command.json \
  --requests /path/to/frozen-requests.jsonl \
  --repetitions 3 \
  --output /path/to/stdio-report.json
```

A report from the echo fixture in CI is only a harness regression. It is not a
CCOS performance result and must not be combined with A09 as though both measured
the same boundary.

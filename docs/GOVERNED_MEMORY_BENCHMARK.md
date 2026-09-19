# A09: governed memory workload

Run from a clean checkout, on an otherwise idle machine where possible:

```sh
cargo build --release --locked -p ccos-enterprise-mcp --example governed_memory_bench
python3 scripts/bench-governed-memory.py --output results/a09.json
```

Defaults: 1k, 10k, 100k assets **per tenant**; one/four tenants; 1,000 requests
per tenant and three independent repetitions. Each case provisions a fresh
directory, then starts two separate query processes against the durable files.
The output includes the source commit, dirty flag, binary/lockfile hashes,
toolchain, platform, complete profile, raw latencies and errors. Failures persist
in the report and cause a nonzero exit. No fallback workload is substituted.

The workload uses 32-dimensional deterministic synthetic vectors, 64-byte
tenant-tagged observations, a 64-bit SimHash, k=8, shortlist=64 and a 4,096-byte
context budget. Synthetic observations remain Unverified; the benchmark explicitly
chooses AnyNonQuarantined, while the production stdio context remains VerifiedOnly.
No synthetic truth labels or claimed retrieval-quality scores are introduced.

## Measured boundary

Each timed query includes a real signed-token identity's `Deployment::admit`,
shared admission-lock contention across tenants, the governed adapter's recall,
tenant/space/lineage/trust admission, bound context assembly and attestation.
Authentication happens once per worker before timing. Each tenant has one query
worker; per-tenant serial and cross-tenant parallel operation are explicit.
Negative controls reject a cross-tenant caller before provider access and check
every returned payload's tenant marker.

Provisioning time includes synthetic population construction, durable publication
and reopen. Recovery is measured separately for each tenant; tenants reopen in
sequence. Both query processes must produce identical output and provider-image
digests. This is a normal fresh-process restart experiment; process killing and
physical power-loss semantics are separate tests.

Latency uses nearest-rank empirical p50/p95/p99; all nanosecond samples are retained,
including the first request (no discarded warmup). Throughput divides completed
requests by concurrent wall time, not summed individual request latencies. RSS is
process-wide Linux VmRSS/VmHWM in KiB, nullable on other systems. It includes the
Rust allocator, all tenants, setup and measurement buffers. The OS file cache is
not flushed. Report sample counts/repetitions; small smoke runs are not SLO evidence.

## Scale qualification and optimization

The previous configuration refused 100k assets: governance exceeded 16 MiB and
recovery configuration allowed at most 16,384 records. The bounded hard maxima
are now 64 MiB of governance, 256 MiB of provider image, and 131,072 records.
The operator must still select a tenant capacity; existing configured quotas are
unchanged. The 32 MiB raw-vector and 16 MiB raw-payload bounds remain in force.
100k at 32 dimensions does not qualify 100k at 768 dimensions.

`GovernedMemorySnapshot` owns validated immutable metadata and its canonical
fingerprint. Selected-generation reads reuse it instead of reconstructing and
serializing the complete governance graph three times per request. There is no
mutable escape or caller-supplied digest. New generations get new snapshots;
batch binding, tenant isolation, lineage, trust and exact payload hashes remain
mandatory. The independent-projection API keeps its full per-call validation.

The real MCP served context uses this same snapshot path after admission. The
benchmark does not measure MCP framing, durable request journaling/settlement,
text encoding, an LLM generator or answer quality. No component cost may be
presented as full service latency.

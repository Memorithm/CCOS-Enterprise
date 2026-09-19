# Governed memory measurement — 2026-09-19

Measured code: `b3af20fc952426eef06dd38115312350b14737f5` (clean worktree). All 18 cases passed, with 90,000 recorded request latencies and exact result/image digest equality across two independent recovery processes per case. Raw data: [JSON](governed-memory-20260919-aarch64.json).

Host: Linux 6.8.12-tegra, aarch64, 14 ARM cores (NVIDIA Thor, reported maximum 2.601 GHz), approximately 122 GiB RAM. Rust 1.89.0, release profile. This was a development host; CPU affinity, thermal state, and competing host work were not controlled. The OS page cache was retained.

Each size is **per tenant**. The four-tenant row has four concurrent workers sharing one `Deployment` admission mutex; each tenant owns an independent recovered adapter. Three repetitions, 1,000 queries per tenant in each of two fresh query processes. Vectors have 32 dimensions and payloads 64 bytes. The identity signature is verified before timing; admission, recall, eligibility, context binding and attestation are timed. MCP transport, durable request settlement, encoder and generator are excluded.

| Assets/tenant | Tenants | p50 ms | p95 ms | p99 ms | Median requests/s | Max query RSS MiB | Max init RSS MiB | Median total recovery s | Disk MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1000 | 1 | 0.049 | 0.059 | 0.107 | 16580.787 | 9.043 | 12.652 | 0.027 | 1.373 |
| 1000 | 4 | 0.050 | 0.065 | 0.173 | 45144.779 | 19.773 | 21.602 | 0.106 | 5.492 |
| 10000 | 1 | 0.117 | 0.130 | 0.188 | 7784.949 | 72.070 | 109.887 | 0.287 | 13.740 |
| 10000 | 4 | 0.117 | 0.139 | 2.927 | 23316.897 | 170.723 | 205.844 | 1.147 | 54.960 |
| 100000 | 1 | 0.548 | 0.666 | 1.043 | 1670.784 | 679.250 | 1007.707 | 2.839 | 137.581 |
| 100000 | 4 | 0.572 | 0.778 | 4.754 | 5344.748 | 1558.176 | 1893.469 | 10.957 | 550.323 |

Quantiles pool raw observations from all six query processes for each profile; they are not averages of percentiles. Throughput is the median of six independently timed process runs. RSS maxima include recovery allocations; initialization is reported separately. Recovery time sums the sequential tenant recovery durations per process. Individual runs and tenant distributions remain in the raw report.

These results qualify this bounded synthetic profile and normal restart equality. They establish neither an SLO nor superiority over RAG, embedding quality, crash/power-loss safety, physical purge or KMS security. In particular, 100k assets at 32 dimensions does not qualify 100k at 768 dimensions. Multi-tenant p99 tails deserve follow-up with longer runs, contention profiles and durable stdio settlement.

Reproduce using the commands in [the benchmark contract](../GOVERNED_MEMORY_BENCHMARK.md) at the measured commit. The report preserves executable and Cargo.lock hashes. Report SHA-256: `54d4a0f780e801b3a6cb92f63130eb0115612077900f01f3f550ec856d2f684f`.

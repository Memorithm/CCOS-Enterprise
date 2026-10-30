# GPU execution path for CCOS dense encode, FPR campaigns and RAG

Status: design note (2026-10-30). Direction from the owner: work runs on GPU only.
Nothing in this note changes CPU CI. GPU code must stay behind Cargo features, so
default builds and hosted CI compile without GPU libraries.

## Current state in CCOS-Enterprise (main `5a638f6`)

- `crates/ccos-dense-encoder` is **CPU-only by design**: pure-Rust f32 BERT/MiniLM
  forward pass (no BLAS, candle or CUDA), parallelised with scoped threads, behind
  `ccos_core::retrieval::Encoder`. `examples/beir_campaign_v3.rs` drives the campaigns.
- `docs/EMBEDDING_MODEL_DECISION.md` says generic tensor and inference work belongs in
  SciRust. Enterprise owns admission, tenancy, quotas and model selection.

## Existing Memorithm GPU tooling (reuse it, don't reinvent it)

| Component | Where | What it gives us |
| --- | --- | --- |
| `scirust-cuda` | Memorithm/scirust | cudarc-based bf16 GEMV/GEMM (tiled, cuBLASLt), dynamic loading |
| `scirust-gpu` `CudaBackend` (feature `cuda`) | scirust `scirust-gpu/src/cuda_compute_adapter.rs` | `RawComputeBackend` GEMM. Returns `BackendError::Unavailable` when no device is present. Compiles without a toolkit |
| `scirust-gpu` `WgpuBackend`/`GpuChain` (feature `wgpu`) | scirust `docs/GPU.md` | Portable WGSL GEMM and VRAM-resident matmul chains, checked against the CPU oracle |
| `scirust-sciagent` CUDA examples | `cuda_forward_bench`, `cuda_decode`, `gpu_forward_parity` | Transformer forward on CUDA plus a parity harness |
| `scirust-core/src/embed.rs` | scirust | `EmbeddingEngine` (MiniLLM, mean-pool, L2). Not yet qualified for retrieval |
| Thor runners | `[self-hosted, Linux, ARM64, scirust-arm64, jetson-thor, internal]` | Jetson Thor CUDA, used by `sciagent-thor-gate.yml` and the `flat-m*-thor` workflows |
| `scripts/thor_gpu_guard.py` | scirust `docs/THOR_GPU_RESERVATION.md` | Advisory lock on `/dev/nvidia0`, occupancy check, exit 75 if unavailable |
| RemoteOps | Memorithm/RemoteOps workflows `*-thor*`, `*-dell*` | Bootstraps the Thor and Dell self-hosted runners |
| Forge | `forge-core/src/bin/run_cuda.rs`, `domains/cuda_kernel.rs` | CUDA kernel assembly and run tooling |

## Proposed design

1. **`ccos-dense-encoder` feature `gpu-cuda`** (off by default) adds an optional
   dependency on `scirust-gpu` (feature `cuda`), pinned by SHA. The BERT linear layers
   (QKV, attention output, FFN) send their GEMMs through `RawComputeBackend`. Tokenizer,
   LayerNorm, GELU and pooling stay unchanged at first, then move into a `GpuChain`-style
   VRAM-resident path so activations don't round-trip to the host.
2. **Backend selection**: `EncoderBackend::{Cpu, Cuda}`. In GPU-only campaign mode
   (`CCOS_ENCODER_BACKEND=cuda`) `Unavailable` is a **hard error**: no silent CPU
   fallback, so no campaign result can come from the CPU by accident. The CPU path is
   still the reference oracle and the default for hosted CI. That is the only "fallback",
   and it already exists.
3. **Parity gate**: on Thor, compare GPU against CPU embeddings on `tests/oracle.json` and
   `tests/oracle_multilingual.json` (cosine ≥ 0.9999, max-abs tolerance documented,
   bf16 accumulation noted). Record backend, device, driver and scirust SHA in the
   campaign manifest.
4. **FPR-v12 invocation** (not started by this note): campaign binaries run with
   `--features gpu-cuda` and `CCOS_ENCODER_BACKEND=cuda`. The manifest fails closed if
   the backend is not `cuda`. RAG ingestion and query encoding reuse the same `Encoder`
   impl.

## RemoteOps / Thor job sketch

```yaml
jobs:
  dense-encoder-gpu-parity:
    runs-on: [self-hosted, Linux, ARM64, jetson-thor, internal]
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - run: ./crates/ccos-dense-encoder/fetch-model.sh
      - run: python3 scripts/thor_gpu_guard.py -- cargo test -p ccos-dense-encoder --features gpu-cuda --release -- --include-ignored gpu_parity
```

`thor_gpu_guard.py` would be vendored from scirust (or invoked from a pinned checkout),
and exit 75 maps to "resource unavailable". Dell runners only take GPU jobs once a GPU
label exists for them in RemoteOps.

## Implemented: `gpu-cuda` feature (CUDA encode)

Status: in `ccos-dense-encoder`, off by default. Hosted CI builds it under
`--all-features` but never runs it on a GPU (no device there, so CUDA tests skip or
check the hard failure).

* **Dependency**: `scirust-cuda` pinned to scirust `master`
  `9943fd881861e6e33a62319997536473e0ee6e1b` (feature `cuda`, cudarc 0.19,
  dynamic loading). This is the engine behind `scirust-gpu::CudaBackend`. The
  encoder uses `CudaChain` directly, not `CudaBackend::gemm_f32`, because the
  latter opens a new context and compiles NVRTC kernels on every call. Weights
  are uploaded once (bf16, kept in VRAM) and the host copy is dropped.
* **What runs on GPU**: every BERT `Linear` (Q, K, V, attention output, FFN in and
  out) as `x · Wᵀ` on cuBLASLt bf16 Tensor cores with fp32 accumulation. The
  activation is uploaded per GEMM, and the bias is added on the host. Tokenizer,
  embeddings, softmax attention, LayerNorm, GELU and pooling still run on the CPU
  (step 2 of the design: a VRAM-resident chain).
* **Selection**: `CCOS_ENCODER_BACKEND=cpu|cuda` (unset means `cpu`, anything else
  is an error). `BertSentenceEncoder::load`/`load_auto` read the variable, and
  `load_with_backend`/`load_auto_with_backend(…, EncoderBackend::Cuda)` set the
  backend explicitly.
* **Hard fail, no CPU fallback**: with `cuda`, the device is opened *before* any
  weights are read. If it is missing (no device, no libcuda/cuBLASLt, or a build
  without `gpu-cuda`), `load` returns `Err("… refusing to fall back to CPU")`. A
  CUDA error during encoding panics instead of returning a zero vector. In CUDA
  mode, batches run serially on the device.
* **Parity bound**: `CUDA_MIN_COS = 0.999` against the fp32 oracle, because of
  bf16 inputs. The CPU path keeps `cos > 0.9999` and `maxabs < 1e-3`.

### Build and run

```bash
# CPU reference (default, what CI runs)
cargo test -p ccos-dense-encoder

# CUDA (Thor / any NVIDIA host with a driver and CUDA 13 libs)
cargo build --release -p ccos-dense-encoder --features gpu-cuda
CCOS_ENCODER_BACKEND=cuda CCOS_DENSE_MODEL_DIR=/path/all-MiniLM-L6-v2 \
  python3 thor_gpu_guard.py -- \
  cargo test --release -p ccos-dense-encoder --features gpu-cuda cuda_ -- --nocapture

# Parity probe: CUDA vs CPU vs oracle JSON, one JSON line per model, exit 0/1/2
CCOS_DENSE_MODEL_DIR=/path/all-MiniLM-L6-v2 \
CCOS_DENSE_MULTI_MODEL_DIR=/path/paraphrase-multilingual-MiniLM-L12-v2 \
  cargo run --release -p ccos-dense-encoder --features gpu-cuda --example cuda_parity
```

Downstream binaries (campaigns, RAG) enable the feature with
`ccos-dense-encoder = { …, features = ["gpu-cuda"] }` and set
`CCOS_ENCODER_BACKEND=cuda`. Every existing `load` call site then fails closed when
no GPU is present.

### Thor workflow

`.github/workflows/dense-encoder-cuda-thor.yml` is `workflow_dispatch` only and not
a required check. It runs on `[self-hosted, Linux, ARM64, jetson-thor, internal]`,
fetches `thor_gpu_guard.py` from the same pinned scirust SHA, and under the guard runs
the `cuda_` tests and the `cuda_parity` example with model directories that are
already on the runner (workflow inputs, no network model fetch).

#### Runner status (checked 2026-10-30)

`Memorithm/CCOS-Enterprise` has **no** self-hosted runner, so a dispatch stays queued. Thor
runners exist but are scoped to other repositories: `tarek-scirust-arm64-01..04`
(`jetson-thor, scirust-arm64, internal`, repo `Memorithm/scirust`) and `thor-remoteops-arm64-01`
(`remoteops, thor, jetson-thor`, repo `Memorithm/RemoteOps`). RemoteOps' bootstrap workflow only
provisions the CHECKUPAUTO.FR runner; it does not cover this repository. No Thor run is claimed
as evidence yet.

#### Registering a Thor runner for this repository (admin on Thor + repo admin)

1. In repo **Settings → Actions → Runners → New self-hosted runner** (Linux, ARM64), take the
   short-lived registration token (or `gh api -X POST
   repos/Memorithm/CCOS-Enterprise/actions/runners/registration-token`; needs repo admin).
2. On Thor, as a dedicated non-root user, in a new directory (for example
   `/opt/actions-runner-ccos`; do not reuse the scirust runner directory):
   ```bash
   ./config.sh --url https://github.com/Memorithm/CCOS-Enterprise --token <TOKEN> \
     --name thor-ccos-arm64-01 --labels jetson-thor,internal --unattended
   sudo ./svc.sh install && sudo ./svc.sh start
   ```
   `self-hosted, Linux, ARM64` are added automatically, which matches the workflow's
   `runs-on: [self-hosted, Linux, ARM64, jetson-thor, internal]`.
3. Toolchain on the runner user: rustup (repo `rust-toolchain.toml`), CUDA 13 driver and libs,
   `nvidia-smi`, `python3`, `curl`.
4. Models (no network fetch in the workflow), at the workflow's default input paths:
   - `/opt/ccos/models/all-MiniLM-L6-v2` (`fetch-model.sh`)
   - `/opt/ccos/models/paraphrase-multilingual-MiniLM-L12-v2` (`fetch-model-multilingual.sh`,
     rev `e8f8c211…5f42`; pass it as the `multi_dir` input).
5. Dispatch: `gh workflow run dense-encoder-cuda-thor.yml --ref main -f
   multi_dir=/opt/ccos/models/paraphrase-multilingual-MiniLM-L12-v2`.

The GPU is shared with the scirust runners; the workflow's `concurrency` group and
`thor_gpu_guard.py` serialise use on this repository's side only.

FPR-v12 is preregistered (`docs/campaigns/2026-10-30-ingest-guard-fpr-v12-prereg.md`) and is
CUDA-only: it refuses to start on CPU and needs this runner (plus the campaign data) first.

## CUDA encode throughput: measured, not yet fixed (2026-10-30)

Measured (no new benchmark; numbers from the campaign `meta` lines):

| Run | Backend | Host | Unique texts | Encode time |
|---|---|---|---|---|
| FPR-v11 (#268) | CPU, 8 threads | Thor CPU | 126,767 | 3,319 s |
| FPR-v12 (#273, run 41094227650) | CUDA (bf16 linears) | Jetson Thor | 126,767 | 6,999 s |

Parity probe (4 items, includes warm-up): multilingual L12 `cpu_ms 87.5` vs `cuda_ms 157.4`;
L6 `cpu_ms 540.6` vs `cuda_ms 284.6`. CUDA is not faster at batch size 1.

Cause, from reading the code (not profiled yet):
1. `BertSentenceEncoder::encode_batch` takes a **serial per-text path** when CUDA is active
   (`texts.iter().map(embed_one_checked)`), while the CPU path fans out over 8 threads. Batch size on
   the GPU is therefore 1 sequence (≤ 128 tokens).
2. Only the linear layers run on the GPU. `CudaLinears::forward` **uploads the activation, runs one
   GEMM and downloads the result synchronously for every linear** (≈ 6 per layer × 12 layers ≈ 72
   host↔device round-trips per text), all behind one `Mutex`. Attention, softmax, LayerNorm, GELU,
   bias add and pooling stay on one CPU thread.
3. So each text pays ~72 launch+sync latencies for tiny GEMMs (`[≤128, 384] × [384, 1536]`) and loses
   the 8-way CPU parallelism: slower than CPU overall.

Follow-up checklist (each change must keep `dense-encoder-cuda-thor.yml` parity ≥ 0.999 and report
measured times, no projected speedups):
- [ ] Profile one 1k-text batch on Thor (`nsys` or timers): split upload / GEMM / download / CPU ops.
- [ ] Overlap CPU work: run `embed_one_checked` from N threads, holding the CUDA mutex only inside
      `forward` (cheapest change; attention/LN then parallelise again).
- [ ] Batch across texts: pad/pack several sequences into one `[Σn, d]` GEMM per linear
      (attention stays per sequence) to raise GEMM size and cut round-trips by the batch factor.
- [ ] Keep activations resident: fuse QKV into one GEMM and avoid download→upload between
      consecutive linears (needs device-side bias/GELU or a fused kernel in SciRust).
- [ ] Re-measure on the FPR corpus (126,767 texts) and record CPU vs CUDA in this table.

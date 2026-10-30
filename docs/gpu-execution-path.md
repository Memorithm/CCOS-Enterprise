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

TODO (ops): register a Thor runner with these labels for **this** repository (today
the runners serve `Memorithm/scirust`), and put the MiniLM model dirs on it. Until
then a dispatch stays queued. No Thor run is claimed as evidence yet.

Not started: FPR-v12 (see step 4).

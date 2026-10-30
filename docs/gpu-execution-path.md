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

## Next PR (engineering)

`ccos-dense-encoder: optional gpu-cuda backend via scirust-gpu CudaBackend`, containing:
the feature-gated dependency, GEMM routing, a fail-closed backend env, a Thor-only
`#[ignore]` parity test, and a workflow_dispatch Thor workflow. Default CPU CI unchanged.

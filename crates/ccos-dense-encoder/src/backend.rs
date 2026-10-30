//! Execution backend selection for [`crate::BertSentenceEncoder`].
//!
//! * [`EncoderBackend::Cpu`] — the pure-Rust f32 reference path (default; hosted CI).
//! * [`EncoderBackend::Cuda`] — every `Linear` (Q/K/V, attention output, FFN in/out) runs as a
//!   resident-weight bf16 Tensor-core GEMM (fp32 accumulation) through SciRust's CUDA backend
//!   (`scirust-cuda`, the engine behind `scirust-gpu::CudaBackend`). Requires the `gpu-cuda`
//!   feature. **No silent CPU fallback**: if CUDA is requested and no device can be opened, the
//!   encoder fails to load; a CUDA error during encoding panics instead of returning CPU output.
//!
//! Selection is explicit ([`crate::BertSentenceEncoder::load_with_backend`]) or by environment
//! variable [`BACKEND_ENV`] (`cpu` | `cuda`, unset ⇒ `cpu`) for [`crate::BertSentenceEncoder::load`]
//! and [`crate::BertSentenceEncoder::load_auto`].

use crate::DenseEncoderError;

/// Environment variable read by [`EncoderBackend::from_env`].
pub const BACKEND_ENV: &str = "CCOS_ENCODER_BACKEND";

/// Where the encoder's dense linear layers execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncoderBackend {
    /// Pure-Rust CPU reference path.
    #[default]
    Cpu,
    /// Exclusive CUDA path (feature `gpu-cuda`); hard failure when unavailable.
    Cuda,
}

impl EncoderBackend {
    /// Parse `cpu` / `cuda` (case-insensitive, surrounding whitespace ignored).
    pub fn parse(s: &str) -> Result<Self, DenseEncoderError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "cpu" => Ok(Self::Cpu),
            "cuda" | "gpu" => Ok(Self::Cuda),
            other => Err(DenseEncoderError(format!(
                "{BACKEND_ENV}={other:?}: expected `cpu` or `cuda`"
            ))),
        }
    }

    /// Read [`BACKEND_ENV`]; unset ⇒ [`EncoderBackend::Cpu`]. Unknown values are an error.
    pub fn from_env() -> Result<Self, DenseEncoderError> {
        match std::env::var(BACKEND_ENV) {
            Ok(v) => Self::parse(&v),
            Err(std::env::VarError::NotPresent) => Ok(Self::Cpu),
            Err(e) => Err(DenseEncoderError(format!("{BACKEND_ENV}: {e}"))),
        }
    }

    /// Stable label (`"cpu"` / `"cuda"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
        }
    }
}

#[cfg(feature = "gpu-cuda")]
pub(crate) use cuda::CudaLinears;
#[cfg(not(feature = "gpu-cuda"))]
pub(crate) use disabled::CudaLinears;

#[cfg(not(feature = "gpu-cuda"))]
mod disabled {
    use crate::DenseEncoderError;

    /// Placeholder when the crate is built without `gpu-cuda`: opening always fails.
    pub(crate) struct CudaLinears;

    impl CudaLinears {
        pub(crate) fn open() -> Result<Self, DenseEncoderError> {
            Err(DenseEncoderError(
                "CCOS_ENCODER_BACKEND=cuda requires building ccos-dense-encoder with \
                 `--features gpu-cuda`; refusing to fall back to CPU"
                    .into(),
            ))
        }
        pub(crate) fn add_weight(
            &mut self,
            _w: &[f32],
            _out: usize,
            _inp: usize,
        ) -> Result<usize, DenseEncoderError> {
            unreachable!("CudaLinears cannot be opened without gpu-cuda")
        }
        pub(crate) fn forward(
            &self,
            _id: usize,
            _x: &[f32],
            _n: usize,
        ) -> Result<Vec<f32>, DenseEncoderError> {
            unreachable!("CudaLinears cannot be opened without gpu-cuda")
        }
    }
}

#[cfg(feature = "gpu-cuda")]
mod cuda {
    use crate::DenseEncoderError;
    use scirust_cuda::{CudaChain, CudaMatrix};
    use std::sync::Mutex;

    /// One CUDA context + cuBLASLt handle and every linear weight resident in VRAM (bf16).
    pub(crate) struct CudaLinears {
        // cudarc handles are used from one thread at a time.
        inner: Mutex<Inner>,
    }

    struct Inner {
        chain: CudaChain,
        weights: Vec<CudaMatrix>,
    }

    impl CudaLinears {
        /// Open CUDA device 0. Errors (never falls back) when no CUDA runtime/device is usable.
        pub(crate) fn open() -> Result<Self, DenseEncoderError> {
            let chain = CudaChain::new().ok_or_else(|| {
                DenseEncoderError(
                    "CCOS_ENCODER_BACKEND=cuda but no CUDA device could be opened \
                     (libcuda/cuBLASLt missing or no GPU); refusing to fall back to CPU"
                        .into(),
                )
            })?;
            Ok(Self {
                inner: Mutex::new(Inner {
                    chain,
                    weights: Vec::new(),
                }),
            })
        }

        /// Upload a row-major `[out, inp]` weight once; returns its handle.
        pub(crate) fn add_weight(
            &mut self,
            w: &[f32],
            out: usize,
            inp: usize,
        ) -> Result<usize, DenseEncoderError> {
            let inner = self.inner.get_mut().map_err(|_| poisoned())?;
            let m = inner
                .chain
                .try_upload(w, out, inp)
                .map_err(|e| DenseEncoderError(format!("cuda weight upload: {e}")))?;
            inner.weights.push(m);
            Ok(inner.weights.len() - 1)
        }

        /// `x · Wᵀ` for `x` `[n, inp]` → `[n, out]` (bias added by the caller).
        pub(crate) fn forward(
            &self,
            id: usize,
            x: &[f32],
            n: usize,
        ) -> Result<Vec<f32>, DenseEncoderError> {
            let inner = self.inner.lock().map_err(|_| poisoned())?;
            let w = &inner.weights[id];
            let a = inner
                .chain
                .try_upload(x, n, w.cols())
                .map_err(|e| DenseEncoderError(format!("cuda activation upload: {e}")))?;
            let c = inner.chain.matmul_bt(&a, w);
            inner
                .chain
                .try_download(&c)
                .map_err(|e| DenseEncoderError(format!("cuda download: {e}")))
        }
    }

    fn poisoned() -> DenseEncoderError {
        DenseEncoderError("cuda backend mutex poisoned".into())
    }
}

//! # Dense sentence encoder for `DocumentMemory`
//!
//! A real neural dense encoder behind [`ccos_core::retrieval::Encoder`], so it can be injected into
//! [`ccos_core::doc_memory::DocumentMemory`] in place of the LSA placeholder used by BEIR campaign v2.
//!
//! * Model: any BERT-family sentence-transformer checkpoint in safetensors form. The reference
//!   model for campaign v3 is `sentence-transformers/all-MiniLM-L6-v2` (d = 384).
//! * Backend: pure-Rust CPU forward pass (f32, safe code, no BLAS / candle / CUDA), parallel over
//!   texts with scoped threads. No network access: the model
//!   directory (`config.json`, `tokenizer.json`, `model.safetensors`) is read from local disk.
//! * Preprocessing (sentence-transformers defaults for MiniLM): in-crate BERT WordPiece tokenizer
//!   (vocab from `tokenizer.json`; clean text, CJK split, accent strip, lower-case), `[CLS] … [SEP]`, truncation to `max_len` tokens
//!   (256), attention-masked **mean pooling** over the last hidden state, then **L2 normalisation**.
//!
//! * Multilingual: `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` (d = 384, 12
//!   layers, `max_seq_length` 128, Apache-2.0) is a `BertModel` with an XLM-R SentencePiece
//!   **Unigram** vocabulary (250 002 pieces). [`BertSentenceEncoder::load`] auto-detects the
//!   tokenizer from `tokenizer.json` `model.type` (see [`Tokenizer`] / [`unigram`]); the forward pass
//!   (absolute positions from 0, token-type 0, mean pooling incl. `<s>`/`</s>`, L2) is unchanged.
//!   Use [`BertSentenceEncoder::load_auto`] to pick `max_len` from `sentence_bert_config.json`.
//!   Fetch with `fetch-model-multilingual.sh`.
//!
//! * Execution backend: see [`backend`]. Default is the CPU reference path; with the optional
//!   `gpu-cuda` feature and `CCOS_ENCODER_BACKEND=cuda`, all linear layers run on CUDA (bf16
//!   Tensor cores, fp32 accumulation) with **no CPU fallback**. See `docs/gpu-execution-path.md`.
//!
//! Replay caveat (same quarantine stance as `neural-embed`): outputs are deterministic on a given
//! machine and build, but bit-exactness across CPUs / BLAS kernels is not promised.

use ccos_core::retrieval::Encoder;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub mod backend;
pub mod unigram;
use backend::CudaLinears;
pub use backend::{EncoderBackend, BACKEND_ENV};
pub mod wordpiece;
use unigram::Unigram;
use wordpiece::WordPiece;

/// Default maximum sequence length for `paraphrase-multilingual-MiniLM-L12-v2`
/// (`sentence_bert_config.json` `max_seq_length`).
pub const MULTILINGUAL_MAX_LEN: usize = 128;

/// Sub-word tokenizer, auto-detected from `tokenizer.json` `model.type`.
#[derive(Debug, Clone)]
pub enum Tokenizer {
    /// BERT WordPiece (`[CLS] … [SEP]`), e.g. all-MiniLM-L6-v2.
    WordPiece(WordPiece),
    /// SentencePiece Unigram (`<s> … </s>`, XLM-R vocabulary), e.g. paraphrase-multilingual-MiniLM-L12-v2.
    Unigram(Unigram),
}

impl Tokenizer {
    /// Parse a `tokenizer.json` and dispatch on `model.type` (`WordPiece` | `Unigram`).
    pub fn from_json(t: &serde_json::Value, max_len: usize) -> Result<Self, String> {
        match t["model"]["type"].as_str() {
            Some("WordPiece") => WordPiece::from_json(t, max_len).map(Self::WordPiece),
            Some("Unigram") => Unigram::from_json(t, max_len).map(Self::Unigram),
            o => Err(format!("tokenizer.json: unsupported model.type {o:?}")),
        }
    }

    /// Load `dir/tokenizer.json`.
    pub fn load(dir: &Path, max_len: usize) -> Result<Self, DenseEncoderError> {
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("tokenizer.json")).map_err(err)?,
        )
        .map_err(err)?;
        Self::from_json(&v, max_len).map_err(err)
    }

    /// Model input ids including the special begin/end tokens, at most `max_len` long.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        match self {
            Self::WordPiece(t) => t.encode(text),
            Self::Unigram(t) => t.encode(text),
        }
    }
}

/// Errors raised while loading a model directory.
#[derive(Debug)]
pub struct DenseEncoderError(pub String);

impl std::fmt::Display for DenseEncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dense encoder: {}", self.0)
    }
}
impl std::error::Error for DenseEncoderError {}

fn err<E: std::fmt::Display>(e: E) -> DenseEncoderError {
    DenseEncoderError(e.to_string())
}

/// Default maximum sequence length (sentence-transformers `max_seq_length` for all-MiniLM-L6-v2).
pub const DEFAULT_MAX_LEN: usize = 256;
/// Default number of worker threads for batch encoding (0 = available parallelism).
pub const DEFAULT_THREADS: usize = 0;

/// Minimum cosine to the fp32 sentence-transformers oracle accepted for the CUDA backend
/// (bf16 Tensor-core inputs, fp32 accumulation). The CPU path keeps `> 0.9999`.
pub const CUDA_MIN_COS: f32 = 0.999;

/// Dense linear layer, `y = x Wᵀ + b`, weight stored row-major `[out, in]`.
struct Linear {
    w: Vec<f32>,
    b: Vec<f32>,
    out: usize,
    inp: usize,
    /// Handle of the resident CUDA copy of `w` (CUDA backend only).
    gpu: Option<usize>,
}

impl Linear {
    /// `x`: `[n, inp]` row-major → `[n, out]`, on CUDA when the weight is resident there.
    fn run(
        &self,
        cuda: Option<&CudaLinears>,
        x: &[f32],
        n: usize,
    ) -> Result<Vec<f32>, DenseEncoderError> {
        match (cuda, self.gpu) {
            (Some(c), Some(id)) => {
                let mut y = c.forward(id, &x[..n * self.inp], n)?;
                for yr in y.chunks_exact_mut(self.out) {
                    for (yo, bo) in yr.iter_mut().zip(&self.b) {
                        *yo += bo;
                    }
                }
                Ok(y)
            }
            (None, None) => Ok(self.forward(x, n)),
            _ => Err(DenseEncoderError("linear/backend mismatch".into())),
        }
    }

    /// CPU reference: `x`: `[n, inp]` row-major → `[n, out]`.
    fn forward(&self, x: &[f32], n: usize) -> Vec<f32> {
        let mut y = vec![0f32; n * self.out];
        for (xr, yr) in x
            .chunks_exact(self.inp)
            .zip(y.chunks_exact_mut(self.out))
            .take(n)
        {
            for ((yo, wr), bo) in yr
                .iter_mut()
                .zip(self.w.chunks_exact(self.inp))
                .zip(&self.b)
            {
                *yo = dot(xr, wr) + bo;
            }
        }
        y
    }
}

/// Eight-lane accumulated dot product (auto-vectorises; fixed summation order ⇒ deterministic).
fn dot(a: &[f32], b: &[f32]) -> f32 {
    let mut acc = [0f32; 8];
    let ca = a.chunks_exact(8);
    let cb = b.chunks_exact(8);
    let (ra, rb) = (ca.remainder(), cb.remainder());
    for (x, y) in ca.zip(cb) {
        for i in 0..8 {
            acc[i] += x[i] * y[i];
        }
    }
    let mut s: f32 = acc.iter().sum();
    for (x, y) in ra.iter().zip(rb) {
        s += x * y;
    }
    s
}

struct LayerNorm {
    g: Vec<f32>,
    b: Vec<f32>,
    eps: f32,
}

impl LayerNorm {
    fn apply(&self, x: &mut [f32]) {
        let d = self.g.len();
        for r in x.chunks_exact_mut(d) {
            let mean = r.iter().sum::<f32>() / d as f32;
            let var = r.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / d as f32;
            let inv = 1.0 / (var + self.eps).sqrt();
            for ((v, g), b) in r.iter_mut().zip(&self.g).zip(&self.b) {
                *v = (*v - mean) * inv * g + b;
            }
        }
    }
}

struct Layer {
    q: Linear,
    k: Linear,
    v: Linear,
    attn_out: Linear,
    ln1: LayerNorm,
    inter: Linear,
    out: Linear,
    ln2: LayerNorm,
}

/// Exact-GELU via erf (HF `hidden_act = "gelu"`). erf: Abramowitz–Stegun 7.1.26 refined in f64.
fn gelu(x: f32) -> f32 {
    let x = x as f64;
    (0.5 * x * (1.0 + erf(x / std::f64::consts::SQRT_2))) as f32
}

/// erf with |error| < 1.2e-7 (Numerical Recipes `erfc` Chebyshev form).
fn erf(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t
        * (-z * z - 1.265_512_23
            + t * (1.000_023_68
                + t * (0.374_091_96
                    + t * (0.096_784_18
                        + t * (-0.186_288_06
                            + t * (0.278_868_07
                                + t * (-1.135_203_98
                                    + t * (1.488_515_87
                                        + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
            .exp();
    if x >= 0.0 {
        1.0 - r
    } else {
        r - 1.0
    }
}

/// BERT sentence encoder (mean pooling + L2 norm). CPU path: pure Rust, no unsafe, no BLAS.
/// Optional CUDA linear path behind feature `gpu-cuda` (see [`backend`]).
pub struct BertSentenceEncoder {
    tokenizer: Tokenizer,
    word: Vec<f32>,
    pos: Vec<f32>,
    typ: Vec<f32>,
    ln_emb: LayerNorm,
    layers: Vec<Layer>,
    dim: usize,
    heads: usize,
    threads: usize,
    backend: EncoderBackend,
    cuda: Option<CudaLinears>,
}

impl std::fmt::Debug for BertSentenceEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BertSentenceEncoder")
            .field("dim", &self.dim)
            .field("layers", &self.layers.len())
            .field("heads", &self.heads)
            .field("backend", &self.backend)
            .finish()
    }
}

/// Minimal safetensors reader (F32 tensors only).
struct SafeTensors {
    header: serde_json::Map<String, serde_json::Value>,
    data: Vec<u8>,
}

impl SafeTensors {
    fn read(path: &Path) -> Result<Self, DenseEncoderError> {
        let bytes = std::fs::read(path).map_err(err)?;
        if bytes.len() < 8 {
            return Err(DenseEncoderError("safetensors: truncated".into()));
        }
        let n = u64::from_le_bytes(bytes[..8].try_into().map_err(err)?) as usize;
        let hdr = bytes
            .get(8..8 + n)
            .ok_or_else(|| DenseEncoderError("safetensors: bad header length".into()))?;
        let header: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(hdr).map_err(err)?;
        Ok(Self {
            header,
            data: bytes[8 + n..].to_vec(),
        })
    }

    fn tensor(&self, name: &str, shape: &[usize]) -> Result<Vec<f32>, DenseEncoderError> {
        let e = self
            .header
            .get(name)
            .ok_or_else(|| DenseEncoderError(format!("missing tensor {name}")))?;
        if e["dtype"] != "F32" {
            return Err(DenseEncoderError(format!(
                "{name}: dtype {} != F32",
                e["dtype"]
            )));
        }
        let got: Vec<usize> = e["shape"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64())
                    .map(|v| v as usize)
                    .collect()
            })
            .unwrap_or_default();
        if got != shape {
            return Err(DenseEncoderError(format!(
                "{name}: shape {got:?} != {shape:?}"
            )));
        }
        let off = &e["data_offsets"];
        let (a, b) = (
            off[0].as_u64().unwrap_or(0) as usize,
            off[1].as_u64().unwrap_or(0) as usize,
        );
        let raw = self
            .data
            .get(a..b)
            .filter(|r| r.len() == 4 * shape.iter().product::<usize>())
            .ok_or_else(|| DenseEncoderError(format!("{name}: bad offsets")))?;
        Ok(raw
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }

    fn linear(&self, p: &str, out: usize, inp: usize) -> Result<Linear, DenseEncoderError> {
        Ok(Linear {
            w: self.tensor(&format!("{p}.weight"), &[out, inp])?,
            b: self.tensor(&format!("{p}.bias"), &[out])?,
            out,
            inp,
            gpu: None,
        })
    }

    fn ln(&self, p: &str, d: usize, eps: f32) -> Result<LayerNorm, DenseEncoderError> {
        Ok(LayerNorm {
            g: self.tensor(&format!("{p}.weight"), &[d])?,
            b: self.tensor(&format!("{p}.bias"), &[d])?,
            eps,
        })
    }
}

impl BertSentenceEncoder {
    /// Load `config.json`, `tokenizer.json` and `model.safetensors` from `dir`.
    /// `threads = 0` uses the available parallelism for batch encoding.
    /// The backend comes from [`BACKEND_ENV`] (unset ⇒ CPU); see [`Self::load_with_backend`].
    pub fn load(dir: &Path, max_len: usize, threads: usize) -> Result<Self, DenseEncoderError> {
        Self::load_with_backend(dir, max_len, threads, EncoderBackend::from_env()?)
    }

    /// Like [`Self::load`] with an explicit backend. [`EncoderBackend::Cuda`] opens the CUDA
    /// device *before* reading weights and returns an error if it is unavailable (or if the crate
    /// was built without `gpu-cuda`) — never a CPU fallback.
    pub fn load_with_backend(
        dir: &Path,
        max_len: usize,
        threads: usize,
        backend: EncoderBackend,
    ) -> Result<Self, DenseEncoderError> {
        let mut cuda = match backend {
            EncoderBackend::Cpu => None,
            EncoderBackend::Cuda => Some(CudaLinears::open()?),
        };
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).map_err(err)?)
                .map_err(err)?;
        let get = |k: &str| {
            cfg.get(k)
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .ok_or_else(|| DenseEncoderError(format!("config.json: {k} missing")))
        };
        if cfg.get("hidden_act").and_then(|v| v.as_str()) != Some("gelu") {
            return Err(DenseEncoderError(
                "only hidden_act = gelu is supported".into(),
            ));
        }
        let (d, inter, nl, heads) = (
            get("hidden_size")?,
            get("intermediate_size")?,
            get("num_hidden_layers")?,
            get("num_attention_heads")?,
        );
        let (vocab, maxpos, ntype) = (
            get("vocab_size")?,
            get("max_position_embeddings")?,
            get("type_vocab_size")?,
        );
        let eps = cfg
            .get("layer_norm_eps")
            .and_then(|v| v.as_f64())
            .unwrap_or(1e-12) as f32;
        let tokenizer = Tokenizer::load(dir, max_len.min(maxpos))?;
        let st = SafeTensors::read(&dir.join("model.safetensors"))?;
        let mut layers = Vec::with_capacity(nl);
        for i in 0..nl {
            let p = format!("encoder.layer.{i}");
            layers.push(Layer {
                q: st.linear(&format!("{p}.attention.self.query"), d, d)?,
                k: st.linear(&format!("{p}.attention.self.key"), d, d)?,
                v: st.linear(&format!("{p}.attention.self.value"), d, d)?,
                attn_out: st.linear(&format!("{p}.attention.output.dense"), d, d)?,
                ln1: st.ln(&format!("{p}.attention.output.LayerNorm"), d, eps)?,
                inter: st.linear(&format!("{p}.intermediate.dense"), inter, d)?,
                out: st.linear(&format!("{p}.output.dense"), d, inter)?,
                ln2: st.ln(&format!("{p}.output.LayerNorm"), d, eps)?,
            });
        }
        if let Some(c) = cuda.as_mut() {
            for l in &mut layers {
                for lin in [
                    &mut l.q,
                    &mut l.k,
                    &mut l.v,
                    &mut l.attn_out,
                    &mut l.inter,
                    &mut l.out,
                ] {
                    lin.gpu = Some(c.add_weight(&lin.w, lin.out, lin.inp)?);
                    // Weights are resident on the device; drop the host copy.
                    lin.w = Vec::new();
                }
            }
        }
        Ok(Self {
            word: st.tensor("embeddings.word_embeddings.weight", &[vocab, d])?,
            pos: st.tensor("embeddings.position_embeddings.weight", &[maxpos, d])?,
            typ: st.tensor("embeddings.token_type_embeddings.weight", &[ntype, d])?,
            ln_emb: st.ln("embeddings.LayerNorm", d, eps)?,
            tokenizer,
            layers,
            dim: d,
            heads,
            backend,
            cuda,
            threads: if threads == 0 {
                std::thread::available_parallelism().map_or(1, |n| n.get())
            } else {
                threads
            },
        })
    }

    /// Like [`Self::load`], with `max_len` taken from `sentence_bert_config.json`
    /// (`max_seq_length`) when present, else [`DEFAULT_MAX_LEN`].
    pub fn load_auto(dir: &Path, threads: usize) -> Result<Self, DenseEncoderError> {
        Self::load_auto_with_backend(dir, threads, EncoderBackend::from_env()?)
    }

    /// Like [`Self::load_auto`] with an explicit backend.
    pub fn load_auto_with_backend(
        dir: &Path,
        threads: usize,
        backend: EncoderBackend,
    ) -> Result<Self, DenseEncoderError> {
        let max_len = std::fs::read_to_string(dir.join("sentence_bert_config.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v["max_seq_length"].as_u64())
            .map_or(DEFAULT_MAX_LEN, |v| v as usize);
        Self::load_with_backend(dir, max_len, threads, backend)
    }

    /// The backend the linear layers run on.
    pub fn backend(&self) -> EncoderBackend {
        self.backend
    }

    /// The tokenizer in use.
    pub fn tokenizer(&self) -> &Tokenizer {
        &self.tokenizer
    }

    /// Encode one text (no padding: one sequence per forward pass).
    fn embed_one(&self, text: &str) -> Result<Vec<f32>, DenseEncoderError> {
        let ids = self.tokenizer.encode(text);
        let mut v = self.embed_packed(std::slice::from_ref(&ids), 1)?;
        Ok(v.pop().unwrap_or_else(|| vec![0.0; self.dim]))
    }

    /// Forward several token sequences at once, **without padding**: the rows of all sequences
    /// are packed into one `[Σnᵢ, d]` activation so every `Linear` runs as a single GEMM over the
    /// whole pack (one H2D/GEMM/D2H per linear per pack on CUDA instead of per text). Attention is
    /// computed strictly per sequence (no cross-sequence keys, no mask needed), and embeddings,
    /// LayerNorm, GELU, residuals and pooling are row-local, so on the CPU path the result is
    /// bit-identical to encoding each sequence alone. `threads` parallelises the row-local and
    /// per-sequence CPU work inside the pack (each row/sequence is still computed by exactly the
    /// same code, so the result does not depend on `threads`).
    fn embed_packed(
        &self,
        seqs: &[Vec<u32>],
        threads: usize,
    ) -> Result<Vec<Vec<f32>>, DenseEncoderError> {
        let d = self.dim;
        let lens: Vec<usize> = seqs.iter().map(Vec::len).collect();
        let n: usize = lens.iter().sum();
        let mut h = vec![0f32; n * d];
        {
            let mut rows = h.chunks_exact_mut(d);
            for ids in seqs {
                for (t, &id) in ids.iter().enumerate() {
                    let row = rows.next().expect("row count matches token count");
                    let (w, ty) = (id as usize, 0usize);
                    let wr = self
                        .word
                        .get(w * d..(w + 1) * d)
                        .ok_or_else(|| DenseEncoderError("token id out of vocab".into()))?;
                    let pr = self
                        .pos
                        .get(t * d..(t + 1) * d)
                        .ok_or_else(|| DenseEncoderError("position out of range".into()))?;
                    for j in 0..d {
                        row[j] = wr[j] + pr[j] + self.typ[ty * d + j];
                    }
                }
            }
        }
        par_rows(&mut h, d, threads, |r| self.ln_emb.apply(r));
        let cu = self.cuda.as_ref();
        for l in &self.layers {
            let (q, k, v) = (
                l.q.run(cu, &h, n)?,
                l.k.run(cu, &h, n)?,
                l.v.run(cu, &h, n)?,
            );
            let ctx = self.attention_packed(&q, &k, &v, &lens, threads);
            let mut a = l.attn_out.run(cu, &ctx, n)?;
            par_rows2(&mut a, &h, d, threads, |x, r| {
                for (x, r) in x.iter_mut().zip(r) {
                    *x += r;
                }
                l.ln1.apply(x);
            });
            let mut m = l.inter.run(cu, &a, n)?;
            par_rows(&mut m, l.inter.out, threads, |r| {
                for x in r.iter_mut() {
                    *x = gelu(*x);
                }
            });
            let mut o = l.out.run(cu, &m, n)?;
            par_rows2(&mut o, &a, d, threads, |x, r| {
                for (x, r) in x.iter_mut().zip(r) {
                    *x += r;
                }
                l.ln2.apply(x);
            });
            h = o;
        }
        let mut out = Vec::with_capacity(seqs.len());
        let mut off = 0;
        for &len in &lens {
            out.push(mean_pool_l2(&h[off * d..(off + len) * d], d));
            off += len;
        }
        Ok(out)
    }

    /// Per-sequence multi-head self-attention over a packed `[Σnᵢ, d]` Q/K/V.
    fn attention_packed(
        &self,
        q: &[f32],
        k: &[f32],
        v: &[f32],
        lens: &[usize],
        threads: usize,
    ) -> Vec<f32> {
        let d = self.dim;
        let mut ctx = vec![0f32; q.len()];
        // Split ctx into per-sequence slices, then distribute sequences over threads.
        let mut jobs: Vec<(usize, &mut [f32])> = Vec::with_capacity(lens.len());
        let mut rest: &mut [f32] = &mut ctx;
        let mut off = 0;
        for &len in lens {
            let (a, b) = std::mem::take(&mut rest).split_at_mut(len * d);
            jobs.push((off, a));
            rest = b;
            off += len;
        }
        let run = |(off, c): &mut (usize, &mut [f32])| {
            let len = c.len() / d.max(1);
            let r = *off * d..(*off + len) * d;
            self.attend(&q[r.clone()], &k[r.clone()], &v[r], len, c);
        };
        let threads = threads.max(1).min(jobs.len().max(1));
        if threads <= 1 {
            jobs.iter_mut().for_each(run);
        } else {
            let per = jobs.len().div_ceil(threads);
            std::thread::scope(|s| {
                for chunk in jobs.chunks_mut(per) {
                    s.spawn(move || chunk.iter_mut().for_each(run));
                }
            });
        }
        ctx
    }

    /// Multi-head attention for one sequence of `n` rows; `ctx` must be zeroed `[n, d]`.
    fn attend(&self, q: &[f32], k: &[f32], v: &[f32], n: usize, ctx: &mut [f32]) {
        let d = self.dim;
        let hd = d / self.heads;
        let scale = 1.0 / (hd as f32).sqrt();
        let mut scores = vec![0f32; n];
        for hh in 0..self.heads {
            let o = hh * hd;
            for i in 0..n {
                let qi = &q[i * d + o..i * d + o + hd];
                let mut mx = f32::NEG_INFINITY;
                for (j, s) in scores.iter_mut().enumerate() {
                    *s = dot(qi, &k[j * d + o..j * d + o + hd]) * scale;
                    mx = mx.max(*s);
                }
                let mut z = 0f32;
                for s in scores.iter_mut() {
                    *s = (*s - mx).exp();
                    z += *s;
                }
                let ci = &mut ctx[i * d + o..i * d + o + hd];
                for (j, s) in scores.iter().enumerate() {
                    let p = s / z;
                    for (c, vv) in ci.iter_mut().zip(&v[j * d + o..j * d + o + hd]) {
                        *c += p * vv;
                    }
                }
            }
        }
    }

    /// CUDA batch path: pack up to [`CUDA_BATCH_ENV`] texts per forward pass (see
    /// [`Self::embed_packed`]). Any CUDA failure panics (no CPU fallback, no zero vectors).
    fn encode_batch_cuda(&self, texts: &[String]) -> Vec<Vec<f32>> {
        let per = cuda_batch_size();
        let mut out = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(per) {
            let seqs: Vec<Vec<u32>> = chunk.iter().map(|t| self.tokenizer.encode(t)).collect();
            match self.embed_packed(&seqs, self.threads) {
                Ok(v) => out.extend(v),
                Err(e) => panic!("ccos-dense-encoder cuda backend failed: {e}"),
            }
        }
        out
    }
}

/// Environment variable: texts packed per CUDA forward pass (default [`DEFAULT_CUDA_BATCH`]).
pub const CUDA_BATCH_ENV: &str = "CCOS_ENCODER_CUDA_BATCH";
/// Default texts per CUDA pack (≤ 32 × max_len rows per GEMM).
pub const DEFAULT_CUDA_BATCH: usize = 32;

fn cuda_batch_size() -> usize {
    std::env::var(CUDA_BATCH_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_CUDA_BATCH)
}

/// Apply `f` to each `row_len` row of `x`, split over up to `threads` scoped threads.
fn par_rows<F: Fn(&mut [f32]) + Sync>(x: &mut [f32], row_len: usize, threads: usize, f: F) {
    let rows = x.len() / row_len.max(1);
    let threads = threads.max(1).min(rows.max(1));
    if threads <= 1 {
        x.chunks_exact_mut(row_len).for_each(&f);
        return;
    }
    let per = rows.div_ceil(threads) * row_len;
    let f = &f;
    std::thread::scope(|s| {
        for c in x.chunks_mut(per) {
            s.spawn(move || c.chunks_exact_mut(row_len).for_each(f));
        }
    });
}

/// Like [`par_rows`] with a read-only companion buffer of the same shape (e.g. residual).
fn par_rows2<F: Fn(&mut [f32], &[f32]) + Sync>(
    x: &mut [f32],
    r: &[f32],
    row_len: usize,
    threads: usize,
    f: F,
) {
    let rows = x.len() / row_len.max(1);
    let threads = threads.max(1).min(rows.max(1));
    let each = |xc: &mut [f32], rc: &[f32]| {
        for (xr, rr) in xc.chunks_exact_mut(row_len).zip(rc.chunks_exact(row_len)) {
            f(xr, rr);
        }
    };
    if threads <= 1 {
        each(x, r);
        return;
    }
    let per = rows.div_ceil(threads) * row_len;
    let each = &each;
    std::thread::scope(|s| {
        for (xc, rc) in x.chunks_mut(per).zip(r.chunks(per)) {
            s.spawn(move || each(xc, rc));
        }
    });
}

impl BertSentenceEncoder {
    /// CPU: errors become a zero vector (historic contract). CUDA: errors panic.
    fn embed_one_checked(&self, text: &str) -> Vec<f32> {
        match self.embed_one(text) {
            Ok(v) => v,
            Err(e) if self.cuda.is_some() => panic!("ccos-dense-encoder cuda backend failed: {e}"),
            Err(_) => vec![0.0; self.dim],
        }
    }
}

/// Mean pooling over all rows of `h` (`[n, d]`, no padding present) followed by L2 normalisation.
pub fn mean_pool_l2(h: &[f32], d: usize) -> Vec<f32> {
    let n = (h.len() / d.max(1)).max(1);
    let mut m = vec![0f32; d];
    for r in h.chunks_exact(d) {
        for (a, b) in m.iter_mut().zip(r) {
            *a += b;
        }
    }
    for a in m.iter_mut() {
        *a /= n as f32;
    }
    let norm = m.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
    m.iter().map(|x| x / norm).collect()
}

impl Encoder for BertSentenceEncoder {
    fn embedding_dim(&self) -> usize {
        self.dim
    }

    fn encode(&mut self, text: &str) -> Vec<f32> {
        self.embed_one_checked(text)
    }

    /// Parallel over texts (scoped threads); output order equals input order and each vector is
    /// computed independently, so results do not depend on the thread count. A failing text yields
    /// a zero vector (never panics).
    ///
    /// CUDA backend: texts are packed [`CUDA_BATCH_ENV`] at a time so each linear layer is one
    /// GEMM per pack; a CUDA failure panics (no CPU fallback, no silent zero vectors).
    fn encode_batch(&mut self, texts: &[String]) -> Vec<Vec<f32>> {
        if self.cuda.is_some() {
            return self.encode_batch_cuda(texts);
        }
        let this: &Self = self;
        let per = texts.len().div_ceil(this.threads.max(1)).max(1);
        std::thread::scope(|s| {
            let hs: Vec<_> = texts
                .chunks(per)
                .map(|c| {
                    s.spawn(move || {
                        c.iter()
                            .map(|t| this.embed_one(t).unwrap_or_else(|_| vec![0.0; this.dim]))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }
}

/// Memoising wrapper: identical texts are encoded once and shared across clones. Lets several
/// `DocumentMemory` arms reuse one corpus encoding without re-running the network.
pub struct CachedEncoder<E: Encoder> {
    inner: Arc<Mutex<E>>,
    cache: Arc<Mutex<HashMap<String, Vec<f32>>>>,
    dim: usize,
}

impl<E: Encoder> Clone for CachedEncoder<E> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            cache: Arc::clone(&self.cache),
            dim: self.dim,
        }
    }
}

impl<E: Encoder> CachedEncoder<E> {
    /// Wrap `inner`.
    pub fn new(inner: E) -> Self {
        let dim = inner.embedding_dim();
        Self {
            inner: Arc::new(Mutex::new(inner)),
            cache: Arc::new(Mutex::new(HashMap::new())),
            dim,
        }
    }

    /// Number of cached texts.
    pub fn cached(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl<E: Encoder> Encoder for CachedEncoder<E> {
    fn embedding_dim(&self) -> usize {
        self.dim
    }

    fn encode(&mut self, text: &str) -> Vec<f32> {
        self.encode_batch(&[text.to_string()])
            .pop()
            .unwrap_or_default()
    }

    fn encode_batch(&mut self, texts: &[String]) -> Vec<Vec<f32>> {
        let missing: Vec<String> = {
            let c = self.cache.lock().expect("cache poisoned");
            let mut seen = std::collections::HashSet::new();
            texts
                .iter()
                .filter(|t| !c.contains_key(*t) && seen.insert((*t).clone()))
                .cloned()
                .collect()
        };
        if !missing.is_empty() {
            let vecs = self
                .inner
                .lock()
                .expect("encoder poisoned")
                .encode_batch(&missing);
            let mut c = self.cache.lock().expect("cache poisoned");
            for (t, v) in missing.into_iter().zip(vecs) {
                c.insert(t, v);
            }
        }
        let c = self.cache.lock().expect("cache poisoned");
        texts.iter().map(|t| c[t].clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_pool_and_normalise() {
        let v = mean_pool_l2(&[1.0, 0.0, 3.0, 4.0], 2);
        let r = std::f32::consts::FRAC_1_SQRT_2;
        assert!((v[0] - r).abs() < 1e-6 && (v[1] - r).abs() < 1e-6);
    }

    #[test]
    fn erf_and_gelu_reference_points() {
        assert!(erf(0.0).abs() < 1e-7);
        assert!((erf(1.0) - 0.842_700_792_9).abs() < 2e-7);
        assert!((erf(-2.0) + 0.995_322_265_0).abs() < 2e-7);
        assert!((gelu(1.0) - 0.841_344_7).abs() < 1e-6);
    }

    #[test]
    fn dot_matches_naive() {
        let a: Vec<f32> = (0..19).map(|i| i as f32 * 0.5).collect();
        let b: Vec<f32> = (0..19).map(|i| 1.0 - i as f32 * 0.1).collect();
        let naive: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        assert!((dot(&a, &b) - naive).abs() < 1e-4);
    }

    struct Count(usize);
    impl Encoder for Count {
        fn embedding_dim(&self) -> usize {
            2
        }
        fn encode(&mut self, t: &str) -> Vec<f32> {
            self.0 += 1;
            vec![t.len() as f32, 1.0]
        }
    }

    #[test]
    fn cache_encodes_each_text_once_across_clones() {
        let mut a = CachedEncoder::new(Count(0));
        let mut b = a.clone();
        let x = a.encode_batch(&["ab".into(), "ab".into(), "c".into()]);
        let y = b.encode("ab");
        assert_eq!(x[0], y);
        assert_eq!(x[2], vec![1.0, 1.0]);
        assert_eq!(a.inner.lock().unwrap().0, 2);
        assert_eq!(a.cached(), 2);
    }

    /// Oracle test against `sentence-transformers` (max_seq_length = 256, mean pooling, normalised)
    /// (reference values in `tests/oracle.json`). Runs only when `CCOS_DENSE_MODEL_DIR` points at a
    /// local all-MiniLM-L6-v2 checkout; skipped otherwise (no network in CI).
    #[test]
    fn oracle_equal_minilm_when_model_present() {
        let Ok(dir) = std::env::var("CCOS_DENSE_MODEL_DIR") else {
            eprintln!("CCOS_DENSE_MODEL_DIR unset: oracle test skipped");
            return;
        };
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../tests/oracle.json")).unwrap();
        let mut enc = BertSentenceEncoder::load_with_backend(
            Path::new(&dir),
            DEFAULT_MAX_LEN,
            DEFAULT_THREADS,
            EncoderBackend::Cpu,
        )
        .unwrap();
        assert_eq!(enc.embedding_dim(), 384);
        let items = oracle["items"].as_array().unwrap();
        let texts: Vec<String> = items
            .iter()
            .map(|i| i["text"].as_str().unwrap().into())
            .collect();
        let got = enc.encode_batch(&texts);
        for (i, item) in items.iter().enumerate() {
            let want: Vec<f32> = item["embedding"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect();
            assert_eq!(got[i].len(), want.len());
            let cos: f32 = got[i].iter().zip(&want).map(|(a, b)| a * b).sum();
            let maxabs = got[i]
                .iter()
                .zip(&want)
                .map(|(a, b)| (a - b).abs())
                .fold(0f32, f32::max);
            assert!(
                cos > 0.9999 && maxabs < 1e-3,
                "item {i}: cos={cos} maxabs={maxabs}"
            );
        }
        // Batch vs single must agree (padding must not leak into pooling).
        let single = enc.encode(&texts[0]);
        let maxabs = single
            .iter()
            .zip(&got[0])
            .map(|(a, b)| (a - b).abs())
            .fold(0f32, f32::max);
        assert!(maxabs < 1e-4, "batch/single mismatch {maxabs}");
    }

    /// Oracle test against `sentence-transformers` for paraphrase-multilingual-MiniLM-L12-v2
    /// (`tests/oracle_multilingual.json`: token ids + embeddings, EN/DE/FR). Runs only when
    /// `CCOS_DENSE_MULTI_MODEL_DIR` points at a local checkout (see `fetch-model-multilingual.sh`).
    #[test]
    fn oracle_equal_multilingual_when_model_present() {
        let Ok(dir) = std::env::var("CCOS_DENSE_MULTI_MODEL_DIR") else {
            eprintln!("CCOS_DENSE_MULTI_MODEL_DIR unset: multilingual oracle test skipped");
            return;
        };
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../tests/oracle_multilingual.json")).unwrap();
        let mut enc = BertSentenceEncoder::load_auto_with_backend(
            Path::new(&dir),
            DEFAULT_THREADS,
            EncoderBackend::Cpu,
        )
        .unwrap();
        assert!(matches!(enc.tokenizer(), Tokenizer::Unigram(_)));
        assert_eq!(enc.embedding_dim(), 384);
        let items = oracle["items"].as_array().unwrap();
        let texts: Vec<String> = items
            .iter()
            .map(|i| i["text"].as_str().unwrap().into())
            .collect();
        let got = enc.encode_batch(&texts);
        for (i, item) in items.iter().enumerate() {
            let ids: Vec<u32> = item["ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(enc.tokenizer().encode(&texts[i]), ids, "item {i} ids");
            let want: Vec<f32> = item["embedding"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect();
            let cos: f32 = got[i].iter().zip(&want).map(|(a, b)| a * b).sum();
            let maxabs = got[i]
                .iter()
                .zip(&want)
                .map(|(a, b)| (a - b).abs())
                .fold(0f32, f32::max);
            assert!(
                cos > 0.9999 && maxabs < 1e-3,
                "item {i}: cos={cos} maxabs={maxabs}"
            );
        }
        // max_seq_length = 128 from sentence_bert_config.json: <s> + 126 + </s>.
        let long = "Wort ".repeat(400);
        assert_eq!(enc.tokenizer().encode(&long).len(), MULTILINGUAL_MAX_LEN);
    }

    /// Write a tiny random BERT (WordPiece) model directory for CPU-only structural tests.
    fn tiny_model_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ccos-tiny-bert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (d, inter, nl, heads, maxpos) = (16usize, 32usize, 2usize, 4usize, 64usize);
        let words = [
            "[PAD]", "[UNK]", "[CLS]", "[SEP]", "hello", "world", "the", "cat", "sat", "on", "mat",
            "##s", "a", "dog", "runs", "fast",
        ];
        let vocab: serde_json::Map<String, serde_json::Value> = words
            .iter()
            .enumerate()
            .map(|(i, w)| (w.to_string(), serde_json::json!(i)))
            .collect();
        let tok = serde_json::json!({
            "normalizer": {"type": "BertNormalizer", "lowercase": true},
            "pre_tokenizer": {"type": "BertPreTokenizer"},
            "model": {"type": "WordPiece", "unk_token": "[UNK]", "vocab": vocab},
        });
        std::fs::write(dir.join("tokenizer.json"), tok.to_string()).unwrap();
        let cfg = serde_json::json!({
            "hidden_act": "gelu", "hidden_size": d, "intermediate_size": inter,
            "num_hidden_layers": nl, "num_attention_heads": heads, "vocab_size": words.len(),
            "max_position_embeddings": maxpos, "type_vocab_size": 1, "layer_norm_eps": 1e-12,
        });
        std::fs::write(dir.join("config.json"), cfg.to_string()).unwrap();
        // Deterministic LCG weights.
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 0.4
        };
        let mut tensors: Vec<(String, Vec<usize>)> = vec![
            (
                "embeddings.word_embeddings.weight".into(),
                vec![words.len(), d],
            ),
            (
                "embeddings.position_embeddings.weight".into(),
                vec![maxpos, d],
            ),
            ("embeddings.token_type_embeddings.weight".into(), vec![1, d]),
            ("embeddings.LayerNorm.weight".into(), vec![d]),
            ("embeddings.LayerNorm.bias".into(), vec![d]),
        ];
        for i in 0..nl {
            let p = format!("encoder.layer.{i}");
            for (n, o, inp) in [
                ("attention.self.query", d, d),
                ("attention.self.key", d, d),
                ("attention.self.value", d, d),
                ("attention.output.dense", d, d),
                ("intermediate.dense", inter, d),
                ("output.dense", d, inter),
            ] {
                tensors.push((format!("{p}.{n}.weight"), vec![o, inp]));
                tensors.push((format!("{p}.{n}.bias"), vec![o]));
            }
            for n in ["attention.output.LayerNorm", "output.LayerNorm"] {
                tensors.push((format!("{p}.{n}.weight"), vec![d]));
                tensors.push((format!("{p}.{n}.bias"), vec![d]));
            }
        }
        let mut header = serde_json::Map::new();
        let mut data: Vec<u8> = Vec::new();
        for (name, shape) in &tensors {
            let cnt: usize = shape.iter().product();
            let a = data.len();
            for _ in 0..cnt {
                let v = if name.ends_with("LayerNorm.weight") {
                    1.0 + rnd()
                } else {
                    rnd()
                };
                data.extend_from_slice(&v.to_le_bytes());
            }
            header.insert(
                name.clone(),
                serde_json::json!({"dtype": "F32", "shape": shape, "data_offsets": [a, data.len()]}),
            );
        }
        let h = serde_json::Value::Object(header).to_string().into_bytes();
        let mut file = (h.len() as u64).to_le_bytes().to_vec();
        file.extend_from_slice(&h);
        file.extend_from_slice(&data);
        std::fs::write(dir.join("model.safetensors"), file).unwrap();
        dir
    }

    /// Packing several texts into one forward pass (the CUDA batching path) must be
    /// bit-identical to encoding each text alone on the CPU path, for any thread count.
    #[test]
    fn packed_forward_is_bit_identical_to_per_text() {
        let dir = tiny_model_dir();
        let mut enc =
            BertSentenceEncoder::load_with_backend(&dir, 32, 3, EncoderBackend::Cpu).unwrap();
        let texts: Vec<String> = [
            "hello world",
            "the cat sat on the mat",
            "a dog runs fast",
            "",
            "cats hello dog dog dog the the mat sat on a world runs fast fast",
            "unknownword",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let single: Vec<Vec<f32>> = texts.iter().map(|t| enc.embed_one(t).unwrap()).collect();
        let seqs: Vec<Vec<u32>> = texts.iter().map(|t| enc.tokenizer.encode(t)).collect();
        for threads in [1, 2, 4, 16] {
            let packed = enc.embed_packed(&seqs, threads).unwrap();
            assert_eq!(packed, single, "threads={threads}");
        }
        assert_eq!(enc.encode_batch(&texts), single);
        for v in &single {
            let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!((n - 1.0).abs() < 1e-5);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backend_parse() {
        assert_eq!(EncoderBackend::parse("").unwrap(), EncoderBackend::Cpu);
        assert_eq!(EncoderBackend::parse(" CPU ").unwrap(), EncoderBackend::Cpu);
        assert_eq!(EncoderBackend::parse("cuda").unwrap(), EncoderBackend::Cuda);
        assert!(EncoderBackend::parse("metal").is_err());
    }

    /// `backend = cuda` must never degrade to CPU: without the feature, or on a host with no NVIDIA
    /// device node (hosted CI), loading fails before any weight is read.
    #[test]
    fn cuda_backend_hard_fails_without_device() {
        let no_device = !cfg!(feature = "gpu-cuda")
            || !(Path::new("/dev/nvidia0").exists() || Path::new("/dev/nvgpu").exists());
        if !no_device {
            eprintln!("NVIDIA device node present: hard-fail test not applicable");
            return;
        }
        let e = BertSentenceEncoder::load_with_backend(
            Path::new("/nonexistent-model-dir"),
            DEFAULT_MAX_LEN,
            1,
            EncoderBackend::Cuda,
        )
        .unwrap_err();
        assert!(e.0.contains("refusing to fall back to CPU"), "{e}");
    }

    /// CUDA parity against `tests/oracle.json` (bf16 GEMM ⇒ looser bound than the CPU oracle).
    /// Runs only with `gpu-cuda`, `CCOS_ENCODER_BACKEND=cuda` and `CCOS_DENSE_MODEL_DIR` set.
    #[cfg(feature = "gpu-cuda")]
    #[test]
    fn cuda_oracle_parity_when_requested() {
        if EncoderBackend::from_env().ok() != Some(EncoderBackend::Cuda) {
            eprintln!("CCOS_ENCODER_BACKEND != cuda: cuda oracle test skipped");
            return;
        }
        let Ok(dir) = std::env::var("CCOS_DENSE_MODEL_DIR") else {
            eprintln!("CCOS_DENSE_MODEL_DIR unset: cuda oracle test skipped");
            return;
        };
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../tests/oracle.json")).unwrap();
        let mut enc = BertSentenceEncoder::load_with_backend(
            Path::new(&dir),
            DEFAULT_MAX_LEN,
            1,
            EncoderBackend::Cuda,
        )
        .expect("cuda requested: device must be available");
        assert_eq!(enc.backend(), EncoderBackend::Cuda);
        for (i, item) in oracle["items"].as_array().unwrap().iter().enumerate() {
            let got = enc.encode(item["text"].as_str().unwrap());
            let want: Vec<f32> = item["embedding"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect();
            let cos: f32 = got.iter().zip(&want).map(|(a, b)| a * b).sum();
            assert!(cos > CUDA_MIN_COS, "item {i}: cuda cos={cos}");
        }
    }
}

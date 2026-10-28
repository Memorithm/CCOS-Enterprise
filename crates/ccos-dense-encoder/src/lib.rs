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
//! Replay caveat (same quarantine stance as `neural-embed`): outputs are deterministic on a given
//! machine and build, but bit-exactness across CPUs / BLAS kernels is not promised.

use ccos_core::retrieval::Encoder;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub mod wordpiece;
use wordpiece::WordPiece;

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

/// Dense linear layer, `y = x Wᵀ + b`, weight stored row-major `[out, in]`.
struct Linear {
    w: Vec<f32>,
    b: Vec<f32>,
    out: usize,
    inp: usize,
}

impl Linear {
    /// `x`: `[n, inp]` row-major → `[n, out]`.
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

/// Pure-Rust CPU BERT sentence encoder (mean pooling + L2 norm). No unsafe, no BLAS, no GPU.
pub struct BertSentenceEncoder {
    tokenizer: WordPiece,
    word: Vec<f32>,
    pos: Vec<f32>,
    typ: Vec<f32>,
    ln_emb: LayerNorm,
    layers: Vec<Layer>,
    dim: usize,
    heads: usize,
    threads: usize,
}

impl std::fmt::Debug for BertSentenceEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BertSentenceEncoder")
            .field("dim", &self.dim)
            .field("layers", &self.layers.len())
            .field("heads", &self.heads)
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
    pub fn load(dir: &Path, max_len: usize, threads: usize) -> Result<Self, DenseEncoderError> {
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
        let tok_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("tokenizer.json")).map_err(err)?,
        )
        .map_err(err)?;
        let tokenizer = WordPiece::from_json(&tok_json, max_len.min(maxpos)).map_err(err)?;
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
        Ok(Self {
            word: st.tensor("embeddings.word_embeddings.weight", &[vocab, d])?,
            pos: st.tensor("embeddings.position_embeddings.weight", &[maxpos, d])?,
            typ: st.tensor("embeddings.token_type_embeddings.weight", &[ntype, d])?,
            ln_emb: st.ln("embeddings.LayerNorm", d, eps)?,
            tokenizer,
            layers,
            dim: d,
            heads,
            threads: if threads == 0 {
                std::thread::available_parallelism().map_or(1, |n| n.get())
            } else {
                threads
            },
        })
    }

    /// Encode one text (no padding: one sequence per forward pass).
    fn embed_one(&self, text: &str) -> Result<Vec<f32>, DenseEncoderError> {
        let ids = self.tokenizer.encode(text);
        let (n, d) = (ids.len(), self.dim);
        let mut h = vec![0f32; n * d];
        for (t, row) in h.chunks_exact_mut(d).enumerate() {
            let (w, ty) = (ids[t] as usize, 0usize);
            let wr = self
                .word
                .get(w * d..(w + 1) * d)
                .ok_or_else(|| DenseEncoderError("token id out of vocab".into()))?;
            for j in 0..d {
                row[j] = wr[j] + self.pos[t * d + j] + self.typ[ty * d + j];
            }
        }
        self.ln_emb.apply(&mut h);
        let hd = d / self.heads;
        let scale = 1.0 / (hd as f32).sqrt();
        let mut scores = vec![0f32; n];
        for l in &self.layers {
            let (q, k, v) = (l.q.forward(&h, n), l.k.forward(&h, n), l.v.forward(&h, n));
            let mut ctx = vec![0f32; n * d];
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
            let mut a = l.attn_out.forward(&ctx, n);
            for (x, r) in a.iter_mut().zip(&h) {
                *x += r;
            }
            l.ln1.apply(&mut a);
            let mut m = l.inter.forward(&a, n);
            for x in m.iter_mut() {
                *x = gelu(*x);
            }
            let mut o = l.out.forward(&m, n);
            for (x, r) in o.iter_mut().zip(&a) {
                *x += r;
            }
            l.ln2.apply(&mut o);
            h = o;
        }
        Ok(mean_pool_l2(&h, d))
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
        self.embed_one(text).unwrap_or_else(|_| vec![0.0; self.dim])
    }

    /// Parallel over texts (scoped threads); output order equals input order and each vector is
    /// computed independently, so results do not depend on the thread count. A failing text yields
    /// a zero vector (never panics).
    fn encode_batch(&mut self, texts: &[String]) -> Vec<Vec<f32>> {
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
        let mut enc =
            BertSentenceEncoder::load(Path::new(&dir), DEFAULT_MAX_LEN, DEFAULT_THREADS).unwrap();
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
}

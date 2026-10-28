//! # Dense sentence encoder for `DocumentMemory`
//!
//! A real neural dense encoder behind [`ccos_core::retrieval::Encoder`], so it can be injected into
//! [`ccos_core::doc_memory::DocumentMemory`] in place of the LSA placeholder used by BEIR campaign v2.
//!
//! * Model: any BERT-family sentence-transformer checkpoint in safetensors form. The reference
//!   model for campaign v3 is `sentence-transformers/all-MiniLM-L6-v2` (d = 384).
//! * Backend: `candle` on **CPU only** (f32). No CUDA / NVIDIA stack, no network access: the model
//!   directory (`config.json`, `tokenizer.json`, `model.safetensors`) is read from local disk.
//! * Preprocessing (sentence-transformers defaults for MiniLM): WordPiece tokenizer from
//!   `tokenizer.json` (lower-casing included), `[CLS] … [SEP]`, truncation to `max_len` tokens
//!   (256), attention-masked **mean pooling** over the last hidden state, then **L2 normalisation**.
//!
//! Replay caveat (same quarantine stance as `neural-embed`): outputs are deterministic on a given
//! machine and build, but bit-exactness across CPUs / BLAS kernels is not promised.

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use ccos_core::retrieval::Encoder;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokenizers::{PaddingParams, Tokenizer, TruncationParams};

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
/// Default encode batch size.
pub const DEFAULT_BATCH: usize = 32;

/// CPU BERT sentence encoder (mean pooling + L2 norm).
pub struct BertSentenceEncoder {
    model: BertModel,
    tokenizer: Tokenizer,
    dim: usize,
    batch: usize,
    device: Device,
}

impl std::fmt::Debug for BertSentenceEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BertSentenceEncoder")
            .field("dim", &self.dim)
            .field("batch", &self.batch)
            .finish()
    }
}

impl BertSentenceEncoder {
    /// Load `config.json`, `tokenizer.json` and `model.safetensors` from `dir`.
    pub fn load(dir: &Path, max_len: usize, batch: usize) -> Result<Self, DenseEncoderError> {
        let device = Device::Cpu;
        let cfg_txt = std::fs::read_to_string(dir.join("config.json")).map_err(err)?;
        let config: Config = serde_json::from_str(&cfg_txt).map_err(err)?;
        let dim: usize = serde_json::from_str::<serde_json::Value>(&cfg_txt)
            .map_err(err)?
            .get("hidden_size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| DenseEncoderError("config.json: hidden_size missing".into()))?
            as usize;
        let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json")).map_err(err)?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: max_len,
                ..Default::default()
            }))
            .map_err(err)?;
        tokenizer.with_padding(Some(PaddingParams::default()));
        // SAFETY-free path: load weights by reading the file (no mmap).
        let bytes = std::fs::read(dir.join("model.safetensors")).map_err(err)?;
        let vb = VarBuilder::from_buffered_safetensors(bytes, DType::F32, &device).map_err(err)?;
        let model = BertModel::load(vb, &config).map_err(err)?;
        Ok(Self {
            model,
            tokenizer,
            dim,
            batch: batch.max(1),
            device,
        })
    }

    fn encode_chunk(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, DenseEncoderError> {
        let enc = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(err)?;
        let n = enc.len();
        let len = enc.iter().map(|e| e.get_ids().len()).max().unwrap_or(0);
        let mut ids = Vec::with_capacity(n * len);
        let mut types = Vec::with_capacity(n * len);
        let mut mask = Vec::with_capacity(n * len);
        for e in &enc {
            ids.extend(e.get_ids().iter().map(|&x| x as i64));
            types.extend(e.get_type_ids().iter().map(|&x| x as i64));
            mask.extend(e.get_attention_mask().iter().map(|&x| x as i64));
        }
        let ids = Tensor::from_vec(ids, (n, len), &self.device).map_err(err)?;
        let types = Tensor::from_vec(types, (n, len), &self.device).map_err(err)?;
        let mask = Tensor::from_vec(mask, (n, len), &self.device).map_err(err)?;
        let hidden = self.model.forward(&ids, &types, Some(&mask)).map_err(err)?;
        let pooled = mean_pool_l2(&hidden, &mask).map_err(err)?;
        pooled.to_vec2::<f32>().map_err(err)
    }
}

/// Attention-masked mean pooling over `hidden` `(n, len, d)` followed by row-wise L2 normalisation.
pub fn mean_pool_l2(hidden: &Tensor, mask: &Tensor) -> candle_core::Result<Tensor> {
    let m = mask.to_dtype(DType::F32)?.unsqueeze(2)?; // (n, len, 1)
    let summed = hidden.broadcast_mul(&m)?.sum(1)?; // (n, d)
    let counts = m.sum(1)?.clamp(1e-9, f64::MAX)?; // (n, 1)
    let mean = summed.broadcast_div(&counts)?;
    let norm = mean.sqr()?.sum_keepdim(1)?.sqrt()?.clamp(1e-12, f64::MAX)?;
    mean.broadcast_div(&norm)
}

impl Encoder for BertSentenceEncoder {
    fn embedding_dim(&self) -> usize {
        self.dim
    }

    fn encode(&mut self, text: &str) -> Vec<f32> {
        self.encode_batch(&[text.to_string()])
            .pop()
            .unwrap_or_default()
    }

    /// Encodes in chunks of `batch`. A failing chunk yields zero vectors (never panics), which ranks
    /// last under cosine; callers that care can check for all-zero rows.
    fn encode_batch(&mut self, texts: &[String]) -> Vec<Vec<f32>> {
        let mut out = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(self.batch) {
            match self.encode_chunk(chunk) {
                Ok(v) => out.extend(v),
                Err(_) => out.extend(chunk.iter().map(|_| vec![0.0; self.dim])),
            }
        }
        out
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
    fn mean_pool_respects_mask_and_normalises() {
        let d = Device::Cpu;
        // n=1, len=3, d=2; third token is padding and must be ignored.
        let h = Tensor::from_vec(vec![1f32, 0., 3., 4., 100., 100.], (1, 3, 2), &d).unwrap();
        let m = Tensor::from_vec(vec![1i64, 1, 0], (1, 3), &d).unwrap();
        let v = mean_pool_l2(&h, &m).unwrap().to_vec2::<f32>().unwrap();
        // mean = (2, 2) -> normalised (1/sqrt2, 1/sqrt2)
        let r = std::f32::consts::FRAC_1_SQRT_2;
        assert_eq!(v.len(), 1);
        assert!((v[0][0] - r).abs() < 1e-6 && (v[0][1] - r).abs() < 1e-6);
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
            BertSentenceEncoder::load(Path::new(&dir), DEFAULT_MAX_LEN, DEFAULT_BATCH).unwrap();
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

//! CUDA-vs-CPU-vs-oracle parity probe for the Thor GPU workflow.
//!
//! ```text
//! CCOS_DENSE_MODEL_DIR=/path/all-MiniLM-L6-v2 \
//!   cargo run --release -p ccos-dense-encoder --features gpu-cuda --example cuda_parity
//! ```
//! Optional `CCOS_DENSE_MULTI_MODEL_DIR` adds the multilingual oracle. Prints one JSON line per
//! model and exits non-zero if CUDA is unavailable (hard fail) or parity is below the bound.

use ccos_core::retrieval::Encoder;
use ccos_dense_encoder::{BertSentenceEncoder, EncoderBackend, CUDA_MIN_COS};
use std::path::Path;
use std::time::Instant;

fn cos(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn run(label: &str, dir: &str, oracle: &str) -> Result<bool, String> {
    let oracle: serde_json::Value = serde_json::from_str(oracle).map_err(|e| e.to_string())?;
    let items = oracle["items"].as_array().ok_or("oracle: items")?;
    let texts: Vec<String> = items
        .iter()
        .map(|i| i["text"].as_str().unwrap_or_default().to_string())
        .collect();
    let p = Path::new(dir);
    let mut cpu = BertSentenceEncoder::load_auto_with_backend(p, 0, EncoderBackend::Cpu)
        .map_err(|e| e.to_string())?;
    let mut gpu = BertSentenceEncoder::load_auto_with_backend(p, 1, EncoderBackend::Cuda)
        .map_err(|e| e.to_string())?;
    let t = Instant::now();
    let c = cpu.encode_batch(&texts);
    let cpu_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let g = gpu.encode_batch(&texts);
    let gpu_ms = t.elapsed().as_secs_f64() * 1e3;
    let (mut min_oracle, mut min_cpu) = (f32::INFINITY, f32::INFINITY);
    for (i, item) in items.iter().enumerate() {
        let want: Vec<f32> = item["embedding"]
            .as_array()
            .ok_or("oracle: embedding")?
            .iter()
            .map(|v| v.as_f64().unwrap_or(f64::NAN) as f32)
            .collect();
        min_oracle = min_oracle.min(cos(&g[i], &want));
        min_cpu = min_cpu.min(cos(&g[i], &c[i]));
    }
    let ok = min_oracle > CUDA_MIN_COS && min_cpu > CUDA_MIN_COS;
    println!(
        "{}",
        serde_json::json!({
            "model": label, "items": texts.len(), "backend": "cuda",
            "min_cos_cuda_vs_oracle": min_oracle, "min_cos_cuda_vs_cpu": min_cpu,
            "bound": CUDA_MIN_COS, "cpu_ms": cpu_ms, "cuda_ms": gpu_ms, "pass": ok,
        })
    );
    Ok(ok)
}

fn main() {
    let mut ok = true;
    let mut ran = false;
    for (label, var, oracle) in [
        (
            "all-MiniLM-L6-v2",
            "CCOS_DENSE_MODEL_DIR",
            include_str!("../tests/oracle.json"),
        ),
        (
            "paraphrase-multilingual-MiniLM-L12-v2",
            "CCOS_DENSE_MULTI_MODEL_DIR",
            include_str!("../tests/oracle_multilingual.json"),
        ),
    ] {
        let Ok(dir) = std::env::var(var) else {
            continue;
        };
        ran = true;
        match run(label, &dir, oracle) {
            Ok(p) => ok &= p,
            Err(e) => {
                eprintln!("{label}: {e}");
                std::process::exit(2);
            }
        }
    }
    if !ran {
        eprintln!("set CCOS_DENSE_MODEL_DIR and/or CCOS_DENSE_MULTI_MODEL_DIR");
        std::process::exit(2);
    }
    std::process::exit(if ok { 0 } else { 1 });
}

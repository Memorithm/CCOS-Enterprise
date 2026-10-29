//! FPR-v1 harness (prereg `docs/campaigns/2026-10-29-ingest-guard-fpr-v1-prereg.md`).
//!
//! Measures the empirical false-alarm rate of `IngestGuard` (Core `ConformalGuard` over the Core
//! `shared_detector` injection probability) on held-out benign BEIR documents, through the real
//! `GovernedDocumentMemory::insert_document` path. Research harness only: nothing here enables a
//! guard in any product path.
//!
//! Usage: `cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr -- \
//!         <scifact/corpus.jsonl> <nfcorpus/corpus.jsonl> <fiqa/corpus.jsonl>`

use std::io::BufRead;

use ccos_core::conformal::ConformalGuard;
use ccos_core::doc_memory::DocRankConfig;
use ccos_core::injection_classifier::shared_detector;
use ccos_core::retrieval::Encoder;
use ccos_core::sanitizer::defang;
use ccos_enterprise_docmemory::{
    DocumentMemoryError, GovernedDocumentMemory, GovernedDocumentWrite, IngestGuard,
};
use ccos_enterprise_memory::{MemoryAssetId, MemorySpace};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use sha2::{Digest, Sha256};

const SCIFACT_SHA: &str = "dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6";
const NFCORPUS_SHA: &str = "10cc83ef1826b1425e6a87090b5140b39b27755d5a27e48215a88611c899991f";
const FIQA_SHA: &str = "ff593e4df9933955dc3af83be0c3fa28ac7465f627e08c2e53593e734d506517";
const SEEDS: u32 = 20;
const ALPHAS: [f64; 3] = [0.05, 0.01, 0.10];

#[derive(Clone, Copy)]
struct NoVec;
impl Encoder for NoVec {
    fn embedding_dim(&self) -> usize {
        0
    }
    fn encode(&mut self, _t: &str) -> Vec<f32> {
        Vec::new()
    }
}

struct Doc {
    id: String,
    text: String,
}

fn load(path: &str, want: &str) -> (Vec<Doc>, usize) {
    let bytes = std::fs::read(path).expect("read corpus");
    let got = hex(&Sha256::digest(&bytes));
    assert_eq!(got, want, "SHA-256 mismatch for {path}: run invalid");
    let (mut docs, mut blank) = (Vec::new(), 0);
    for line in bytes.lines() {
        let line = line.expect("utf8 line");
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).expect("json");
        let id = v["_id"].as_str().expect("_id").to_string();
        let title = v["title"].as_str().unwrap_or("");
        let body = v["text"].as_str().unwrap_or("");
        if title.trim().is_empty() && body.trim().is_empty() {
            blank += 1;
            continue;
        }
        docs.push(Doc {
            id,
            text: format!("{title}\n\n{body}"),
        });
    }
    (docs, blank)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn score(text: &str) -> f64 {
    shared_detector().injection_probability(&defang(text).0) as f64
}

fn is_cal(seed: u32, id: &str) -> bool {
    Sha256::digest(format!("ingest-fpr-v1:{seed}:{id}").as_bytes())[0] % 2 == 0
}

/// Clopper–Pearson 95% interval by bisection on the binomial CDF (no external stats crate).
fn clopper_pearson(k: usize, n: usize) -> (f64, f64) {
    fn cdf(k: usize, n: usize, p: f64) -> f64 {
        // P(X <= k), log-space terms.
        let (lp, lq) = (p.ln(), (1.0 - p).ln());
        let mut lc = 0.0f64; // ln C(n, 0)
        let mut s = 0.0;
        for i in 0..=k {
            if i > 0 {
                lc += ((n - i + 1) as f64).ln() - (i as f64).ln();
            }
            s += (lc + i as f64 * lp + (n - i) as f64 * lq).exp();
        }
        s
    }
    let bisect = |f: &dyn Fn(f64) -> bool| {
        let (mut lo, mut hi) = (0.0f64, 1.0f64);
        for _ in 0..100 {
            let mid = 0.5 * (lo + hi);
            if f(mid) {
                hi = mid
            } else {
                lo = mid
            }
        }
        0.5 * (lo + hi)
    };
    let lower = if k == 0 {
        0.0
    } else {
        // smallest p with P(X >= k) >= 0.025  <=>  1 - cdf(k-1) >= 0.025
        bisect(&|p| 1.0 - cdf(k - 1, n, p) >= 0.025)
    };
    let upper = if k == n {
        1.0
    } else {
        // smallest p with cdf(k) <= 0.025
        bisect(&|p| cdf(k, n, p) <= 0.025)
    };
    (lower, upper)
}

/// Count `Flagged` refusals when inserting `texts` through the real Enterprise path.
fn flagged_through_insert(guard: ConformalGuard, texts: &[&str]) -> usize {
    let ig = IngestGuard::new(guard, score as fn(&str) -> f64).expect("calibrated guard");
    let mut mem = GovernedDocumentMemory::with_guard(|| NoVec, DocRankConfig::default(), ig);
    let tenant = TenantId::new("fpr-v1").unwrap();
    let asset = MemoryAssetId::new("probe").unwrap();
    let space = MemorySpace::Tenant;
    let mut k = 0;
    for t in texts {
        let w = GovernedDocumentWrite {
            asset_id: &asset,
            space: &space,
            text: t,
        };
        match mem.insert_document(TenantScope::new(tenant.clone(), w)) {
            Ok(()) => {}
            Err(DocumentMemoryError::Flagged { .. }) => k += 1,
            Err(e) => panic!("unexpected refusal: {e}"),
        }
    }
    k
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 3, "usage: <scifact> <nfcorpus> <fiqa> corpus.jsonl");
    let (sci, sci_blank) = load(&args[0], SCIFACT_SHA);
    let model_fp = shared_detector().model().fingerprint();
    let sci_scores: Vec<f64> = sci.iter().map(|d| score(&d.text)).collect();
    let mut sorted = sci_scores.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mut distinct = sorted.clone();
    distinct.dedup();
    println!(
        "{}",
        serde_json::json!({"kind":"meta","model_fingerprint":model_fp,"scifact_docs":sci.len(),
            "scifact_blank":sci_blank,"score_min":sorted[0],"score_median":sorted[sorted.len()/2],
            "score_max":sorted[sorted.len()-1],"distinct_scores":distinct.len(),
            "scores_eq_1":sci_scores.iter().filter(|s| **s >= 1.0).count(),
            "scores_ge_0_5":sci_scores.iter().filter(|s| **s >= 0.5).count()})
    );

    let mut seed0_guard = None;
    for &alpha in &ALPHAS {
        let mut fprs = Vec::new();
        for seed in 0..SEEDS {
            let (mut cal, mut test) = (Vec::new(), Vec::new());
            for (d, s) in sci.iter().zip(&sci_scores) {
                if is_cal(seed, &d.id) {
                    cal.push(*s)
                } else {
                    test.push(d.text.as_str())
                }
            }
            let guard = ConformalGuard::calibrate(&cal, alpha);
            let k = flagged_through_insert(guard, &test);
            let fpr = k as f64 / test.len() as f64;
            let (lo, hi) = clopper_pearson(k, test.len());
            println!(
                "{}",
                serde_json::json!({"kind":"split","alpha":alpha,"seed":seed,"n_cal":cal.len(),
                    "n_test":test.len(),"threshold":guard.threshold(),"flagged":k,"fpr":fpr,
                    "cp95_lo":lo,"cp95_hi":hi})
            );
            if seed == 0 && alpha == 0.05 {
                seed0_guard = Some(guard);
            }
            fprs.push(fpr);
        }
        let n = fprs.len() as f64;
        let m = fprs.iter().sum::<f64>() / n;
        let sd = (fprs.iter().map(|f| (f - m).powi(2)).sum::<f64>() / (n - 1.0)).sqrt();
        let se = sd / n.sqrt();
        let verdict = if distinct.len() < 100 {
            "INCONCLUSIVE(degenerate)"
        } else if m <= alpha {
            "CONFIRMED"
        } else if m - 1.729 * se > alpha {
            "REFUTED"
        } else {
            "INCONCLUSIVE"
        };
        println!(
            "{}",
            serde_json::json!({"kind":"summary","alpha":alpha,"seeds":SEEDS,"mean_fpr":m,"sd":sd,
                "se":se,"rule_verdict":verdict,"primary":alpha==0.05})
        );
    }

    let guard = seed0_guard.expect("seed 0");
    for (name, path, sha) in [
        ("nfcorpus", &args[1], NFCORPUS_SHA),
        ("fiqa", &args[2], FIQA_SHA),
    ] {
        let (docs, blank) = load(path, sha);
        let texts: Vec<&str> = docs.iter().map(|d| d.text.as_str()).collect();
        let k = flagged_through_insert(guard, &texts);
        let (lo, hi) = clopper_pearson(k, texts.len());
        println!(
            "{}",
            serde_json::json!({"kind":"shift","corpus":name,"alpha":0.05,"threshold":guard.threshold(),
                "n":texts.len(),"blank":blank,"flagged":k,"fpr":k as f64/texts.len() as f64,
                "cp95_lo":lo,"cp95_hi":hi,"guarantee_applies":false})
        );
    }
}

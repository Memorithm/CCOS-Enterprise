//! FPR-v3 harness (prereg `docs/campaigns/2026-10-29-ingest-guard-fpr-v3-prereg.md`).
//!
//! Same protocol as FPR-v2 but the score is the length-normalised margin
//! `(margin - prior_margin) / max(1, n_features)` (higher = more injection-like).
//! Research harness only: enables nothing.
//!
//! Usage: `cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v3 -- \
//!         <scifact> <nfcorpus> <fiqa> <deepset-prompt-injections.jsonl>`

use std::io::BufRead;

use ccos_core::conformal::ConformalGuard;
use ccos_core::doc_memory::DocRankConfig;
use ccos_core::hashing_tokenizer::HashingTokenizer;
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
const DEEPSET_SHA: &str = "2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8";
const MODEL_FP: &str = "1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8";
const TRAIN_SRC: &str = include_str!("../../../core/examples/train_injection.rs");
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

fn n_features(defanged: &str) -> usize {
    static T: std::sync::OnceLock<HashingTokenizer> = std::sync::OnceLock::new();
    T.get_or_init(HashingTokenizer::new)
        .features(defanged)
        .len()
}

/// FPR-v3 score (prereg §2): mean per-feature-occurrence margin contribution, prior removed.
fn score(text: &str) -> f64 {
    let t = defang(text).0;
    let e = shared_detector().explain(&t);
    (e.margin as f64 - e.prior_margin as f64) / (n_features(&t).max(1) as f64)
}

/// v2 raw margin, descriptive reference only.
fn raw_margin(text: &str) -> f64 {
    shared_detector().explain(&defang(text).0).margin as f64
}

fn ranks(v: &[f64]) -> Vec<f64> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    idx.sort_by(|&a, &b| v[a].total_cmp(&v[b]));
    let mut r = vec![0.0; v.len()];
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len() && v[idx[j + 1]] == v[idx[i]] {
            j += 1;
        }
        for k in i..=j {
            r[idx[k]] = (i + j) as f64 / 2.0;
        }
        i = j + 1;
    }
    r
}

fn spearman(a: &[f64], b: &[f64]) -> f64 {
    let (ra, rb) = (ranks(a), ranks(b));
    let n = a.len() as f64;
    let (ma, mb) = (ra.iter().sum::<f64>() / n, rb.iter().sum::<f64>() / n);
    let (mut c, mut va, mut vb) = (0.0, 0.0, 0.0);
    for i in 0..a.len() {
        c += (ra[i] - ma) * (rb[i] - mb);
        va += (ra[i] - ma).powi(2);
        vb += (rb[i] - mb).powi(2);
    }
    c / (va * vb).sqrt()
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
    let tenant = TenantId::new("fpr-v3").unwrap();
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

fn norm(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// String literals of the `BENIGN` and `INJECTION` arrays of the Core trainer (leakage check).
fn training_strings() -> Vec<String> {
    let mut out = Vec::new();
    for name in ["const BENIGN", "const INJECTION"] {
        let start = TRAIN_SRC.find(name).expect("trainer array");
        let block = &TRAIN_SRC[start..];
        let block = &block[block.find("= &[").unwrap()..block.find("\n];").unwrap()];
        for line in block.lines() {
            let l = line.trim();
            if l.starts_with('"') {
                let lit: String = serde_json::from_str(l.trim_end_matches(',')).expect("literal");
                out.push(norm(&defang(&lit).0));
            }
        }
    }
    out
}

fn load_deepset(path: &str) -> (Vec<String>, Vec<String>, usize, usize) {
    let bytes = std::fs::read(path).expect("read deepset");
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        DEEPSET_SHA,
        "deepset SHA mismatch: run invalid"
    );
    let train = training_strings();
    assert!(train.len() >= 50, "trainer parse");
    let (mut pos, mut neg, mut blank, mut leaked) = (Vec::new(), Vec::new(), 0, 0);
    for line in bytes.lines() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let t = v["text"].as_str().unwrap().to_string();
        if t.trim().is_empty() {
            blank += 1;
            continue;
        }
        if v["label"].as_i64() == Some(1) {
            let n = norm(&defang(&t).0);
            if train
                .iter()
                .any(|s| n.contains(s.as_str()) || s.contains(n.as_str()))
            {
                leaked += 1;
                continue;
            }
            pos.push(t);
        } else {
            neg.push(t);
        }
    }
    (pos, neg, blank, leaked)
}

fn summary(v: &[f64]) -> serde_json::Value {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let mut d = s.clone();
    d.dedup();
    serde_json::json!({"n":s.len(),"min":s[0],"median":s[s.len()/2],"max":s[s.len()-1],"distinct":d.len()})
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        4,
        "usage: <scifact> <nfcorpus> <fiqa> <deepset.jsonl>"
    );
    let model_fp = shared_detector().model().fingerprint();
    assert_eq!(
        model_fp, MODEL_FP,
        "model fingerprint mismatch: run invalid"
    );
    assert_eq!(
        HashingTokenizer::new().dim(),
        shared_detector().model().dim,
        "tokenizer/model dim mismatch: run invalid"
    );
    let (sci, sci_blank) = load(&args[0], SCIFACT_SHA);
    let (inj, ds_neg, ds_blank, leaked) = load_deepset(&args[3]);
    let sci_scores: Vec<f64> = sci.iter().map(|d| score(&d.text)).collect();
    let inj_scores: Vec<f64> = inj.iter().map(|t| score(t)).collect();
    let inj_refs: Vec<&str> = inj.iter().map(|s| s.as_str()).collect();
    let sci_n: Vec<f64> = sci
        .iter()
        .map(|d| n_features(&defang(&d.text).0) as f64)
        .collect();
    let inj_n_feat: Vec<f64> = inj
        .iter()
        .map(|t| n_features(&defang(t).0) as f64)
        .collect();
    let sci_n_le1 = sci_n.iter().filter(|n| **n <= 1.0).count();
    let bmax = sci_scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let allmax = inj_scores.iter().cloned().fold(bmax, f64::max);
    let n_distinct = summary(&sci_scores)["distinct"].as_u64().unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"meta","model_fingerprint":model_fp,"scifact_docs":sci.len(),
            "scifact_blank":sci_blank,"scifact_scores":summary(&sci_scores),
            "inj_n":inj.len(),"inj_leak_excluded":leaked,"deepset_blank":ds_blank,
            "deepset_neg_n":ds_neg.len(),"inj_scores":summary(&inj_scores),
            "scifact_eq_max":sci_scores.iter().filter(|s| **s == bmax).count(),
            "scifact_n_features":summary(&sci_n),"inj_n_features":summary(&inj_n_feat),
            "scifact_n_le1":sci_n_le1,"spearman_score_n_scifact":spearman(&sci_scores,&sci_n),
            "spearman_score_n_inj":spearman(&inj_scores,&inj_n_feat)})
    );

    let mut seed0 = None;
    let mut degenerate_reasons: Vec<String> = Vec::new();
    for &alpha in &ALPHAS {
        let (mut fprs, mut tprs) = (Vec::new(), Vec::new());
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
            let kt = flagged_through_insert(guard, &inj_refs);
            let tpr = kt as f64 / inj_refs.len() as f64;
            let (tlo, thi) = clopper_pearson(kt, inj_refs.len());
            let thr = guard.threshold();
            let ties = sci_scores.iter().filter(|s| **s == thr).count();
            println!(
                "{}",
                serde_json::json!({"kind":"split","alpha":alpha,"seed":seed,"n_cal":cal.len(),
                    "n_test":test.len(),"threshold":thr,"scifact_ties_at_threshold":ties,
                    "flagged":k,"fpr":fpr,"cp95_lo":lo,"cp95_hi":hi,"inj_n":inj_refs.len(),
                    "inj_flagged":kt,"tpr":tpr,"tpr_cp95_lo":tlo,"tpr_cp95_hi":thi})
            );
            if seed == 0 && alpha == 0.05 {
                let one_pct = sci_scores.len() as f64 * 0.01;
                if n_distinct < 100 {
                    degenerate_reasons.push("a:<100 distinct".into())
                }
                if !thr.is_finite() {
                    degenerate_reasons.push("b:threshold not finite".into())
                }
                if ties as f64 > one_pct {
                    degenerate_reasons.push("c:>1% ties at threshold".into())
                }
                if sci_scores.iter().filter(|s| **s == bmax).count() as f64 > one_pct {
                    degenerate_reasons.push("d:>1% at benign max".into())
                }
                if thr >= allmax {
                    degenerate_reasons.push("e:threshold >= max score".into())
                }
                if k == 0 {
                    degenerate_reasons.push("f:seed-0 benign test flagged == 0".into())
                }
                if sci_n_le1 as f64 > one_pct {
                    degenerate_reasons.push("g:>1% SciFact with n<=1".into())
                }
                seed0 = Some((guard, kt, tlo));
            }
            fprs.push(fpr);
            tprs.push(tpr);
        }
        let n = fprs.len() as f64;
        let m = fprs.iter().sum::<f64>() / n;
        let sd = (fprs.iter().map(|f| (f - m).powi(2)).sum::<f64>() / (n - 1.0)).sqrt();
        let se = sd / n.sqrt();
        let mt = tprs.iter().sum::<f64>() / n;
        let degenerate = !degenerate_reasons.is_empty();
        let verdict = if m - 1.729 * se > alpha {
            "REFUTED"
        } else if degenerate {
            "INCONCLUSIVE(degenerate)"
        } else if m <= alpha {
            "CONFIRMED"
        } else {
            "INCONCLUSIVE"
        };
        println!(
            "{}",
            serde_json::json!({"kind":"summary","alpha":alpha,"seeds":SEEDS,"mean_fpr":m,"sd":sd,
                "se":se,"mean_tpr":mt,"degenerate_reasons":degenerate_reasons,
                "fpr_verdict":verdict,"primary":alpha==0.05})
        );
    }

    let (guard, kt, tlo) = seed0.expect("seed 0");
    println!(
        "{}",
        serde_json::json!({"kind":"detection","alpha":0.05,"seed":0,"threshold":guard.threshold(),
            "inj_n":inj_refs.len(),"inj_flagged":kt,"tpr_cp95_lo":tlo,
            "detection_verdict": if tlo > 0.05 {"NON-TRIVIAL"} else {"TRIVIAL/NEGATIVE"}})
    );
    {
        // Descriptive reference (prereg §6): v2 raw margin, seed-0 split, alpha 0.05, no verdict.
        let cal: Vec<f64> = sci
            .iter()
            .filter(|d| is_cal(0, &d.id))
            .map(|d| raw_margin(&d.text))
            .collect();
        let g = ConformalGuard::calibrate(&cal, 0.05);
        let k = inj.iter().filter(|t| g.flags(raw_margin(t))).count();
        println!(
            "{}",
            serde_json::json!({"kind":"reference_v2_raw_margin","alpha":0.05,"seed":0,
                "threshold":g.threshold(),"inj_n":inj.len(),"inj_flagged":k,"descriptive_only":true})
        );
    }
    let mut shifts: Vec<(&str, Vec<String>, usize)> = Vec::new();
    for (name, path, sha) in [
        ("nfcorpus", &args[1], NFCORPUS_SHA),
        ("fiqa", &args[2], FIQA_SHA),
    ] {
        let (docs, blank) = load(path, sha);
        shifts.push((name, docs.into_iter().map(|d| d.text).collect(), blank));
    }
    shifts.push(("deepset_label0", ds_neg, 0));
    for (name, texts, blank) in shifts {
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let k = flagged_through_insert(guard, &refs);
        let (lo, hi) = clopper_pearson(k, refs.len());
        println!(
            "{}",
            serde_json::json!({"kind":"shift","corpus":name,"alpha":0.05,"threshold":guard.threshold(),
                "n":refs.len(),"blank":blank,"flagged":k,"fpr":k as f64/refs.len() as f64,
                "cp95_lo":lo,"cp95_hi":hi,"guarantee_applies":false})
        );
    }
}

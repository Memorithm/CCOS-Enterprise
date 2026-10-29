//! FPR-v6 harness (prereg `docs/campaigns/2026-10-29-ingest-guard-fpr-v6-prereg.md`).
//!
//! Same research-only L2 logistic regression as v5, but informal benign chat (Dolly-15k
//! instructions, a source distinct from deepset label 0) is added to training negatives and the
//! `ConformalGuard` threshold is the max of per-pool thresholds (FiQA cal, Dolly cal). deepset
//! label 0 is an untouched control (never trained or calibrated on).
//! Core (model, tokenizer, score) is untouched. Research harness only: enables nothing.
//!
//! Usage: `cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v6 -- \
//!         <scifact> <nfcorpus> <fiqa> <deepset-prompt-injections.jsonl> <dolly-15k.jsonl> <out-model.json>`

use std::collections::HashSet;
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
const DOLLY_SHA: &str = "2df9083338b4abd6bceb5635764dab5d833b393b55759dffb0959b6fcbf794ec";
const MODEL_FP: &str = "1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8";
const TRAIN_SRC: &str = include_str!("../../../core/examples/train_injection.rs");
const SEEDS: u32 = 10;
const ALPHAS: [f64; 3] = [0.05, 0.01, 0.10];
const LAMBDAS: [f64; 3] = [1e-5, 1e-4, 1e-3];
const ITERS: usize = 400;
const THREADS: usize = 8;
const DELTA: f64 = 0.0025;
const T95_9: f64 = 1.833;
const CHAT_CONTROL_MAX: f64 = 0.10;
const TPR_USEFUL: f64 = 0.5;
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

type Kv = Vec<(String, String)>;
fn load_deepset_v5(path: &str) -> (Kv, Kv, usize, usize) {
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
        let key = format!("{}:{}", v["split"].as_str().unwrap(), v["row"]);
        if v["label"].as_i64() == Some(1) {
            let n = norm(&defang(&t).0);
            if train
                .iter()
                .any(|s| n.contains(s.as_str()) || s.contains(n.as_str()))
            {
                leaked += 1;
                continue;
            }
            pos.push((key, t));
        } else {
            neg.push((key, t));
        }
    }
    (pos, neg, blank, leaked)
}

/// Core-trainer `INJECTION` literals (OOD probe, never trained on).
fn core_injections() -> Vec<String> {
    let start = TRAIN_SRC.find("const INJECTION").expect("trainer array");
    let block = &TRAIN_SRC[start..];
    let block = &block[block.find("= &[").unwrap()..block.find("\n];").unwrap()];
    block
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('"'))
        .map(|l| serde_json::from_str::<String>(l.trim_end_matches(',')).expect("literal"))
        .collect()
}

fn split_hash(corpus: &str, seed: u32, key: &str) -> [u8; 32] {
    Sha256::digest(format!("ingest-fpr-v6:{corpus}:{seed}:{key}").as_bytes()).into()
}

/// Sparse feature map φ(x) = log1p(x)/‖log1p(x)‖₂ over the Core tokenizer count vector.
type Sparse = Vec<(u16, f64)>;
fn phi(text: &str) -> Sparse {
    static T: std::sync::OnceLock<HashingTokenizer> = std::sync::OnceLock::new();
    let x = T
        .get_or_init(HashingTokenizer::new)
        .count_vector(&defang(text).0);
    let mut v: Sparse = x
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0.0)
        .map(|(i, c)| (i as u16, (*c as f64).ln_1p()))
        .collect();
    let n = v.iter().map(|(_, a)| a * a).sum::<f64>().sqrt();
    if n > 0.0 {
        for e in &mut v {
            e.1 /= n;
        }
    }
    v
}

#[derive(Clone)]
struct Lr {
    w: Vec<f64>,
    b: f64,
}
impl Lr {
    fn z(&self, x: &Sparse) -> f64 {
        self.b + x.iter().map(|(i, a)| self.w[*i as usize] * a).sum::<f64>()
    }
    fn score_text(&self, t: &str) -> f64 {
        self.z(&phi(t))
    }
}

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

/// Weighted logistic loss + gradient (normalised by Σw), fixed-order chunked reduction.
fn loss_grad(data: &[(&Sparse, f64, f64)], m: &Lr, lambda: f64) -> (f64, Vec<f64>, f64) {
    let dim = m.w.len();
    let chunk = data.len().div_ceil(THREADS).max(1);
    let parts: Vec<(f64, Vec<f64>, f64, f64)> = std::thread::scope(|sc| {
        let hs: Vec<_> = data
            .chunks(chunk)
            .map(|c| {
                sc.spawn(move || {
                    let (mut l, mut g, mut gb, mut ws) = (0.0, vec![0.0; dim], 0.0, 0.0);
                    for (x, y, wt) in c {
                        let z = m.z(x);
                        // log(1+exp(-s z)) with s = ±1, stable
                        let s = if *y > 0.5 { 1.0 } else { -1.0 };
                        let u = -s * z;
                        l += wt
                            * (if u > 0.0 {
                                u + (-u).exp().ln_1p()
                            } else {
                                u.exp().ln_1p()
                            });
                        let r = wt * (sigmoid(z) - y);
                        for (i, a) in x.iter() {
                            g[*i as usize] += r * a;
                        }
                        gb += r;
                        ws += wt;
                    }
                    (l, g, gb, ws)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let (mut l, mut g, mut gb, mut ws) = (0.0, vec![0.0; dim], 0.0, 0.0);
    for (pl, pg, pb, pw) in parts {
        l += pl;
        for (a, b) in g.iter_mut().zip(pg) {
            *a += b;
        }
        gb += pb;
        ws += pw;
    }
    let reg: f64 = m.w.iter().map(|v| v * v).sum::<f64>();
    for (gi, wi) in g.iter_mut().zip(&m.w) {
        *gi = *gi / ws + lambda * wi;
    }
    (l / ws + 0.5 * lambda * reg, g, gb / ws)
}

/// Nesterov accelerated gradient, step 1/(0.5+λ), ITERS iterations, zero init (prereg §1).
fn fit(data: &[(&Sparse, f64, f64)], lambda: f64) -> (Lr, f64) {
    let dim = HashingTokenizer::new().dim();
    let eta = 1.0 / (0.5 + lambda);
    let mut cur = Lr {
        w: vec![0.0; dim],
        b: 0.0,
    };
    let mut prev = cur.clone();
    for k in 1..=ITERS {
        let mom = (k as f64 - 1.0) / (k as f64 + 2.0);
        let y = Lr {
            w: cur
                .w
                .iter()
                .zip(&prev.w)
                .map(|(c, p)| c + mom * (c - p))
                .collect(),
            b: cur.b + mom * (cur.b - prev.b),
        };
        let (_, g, gb) = loss_grad(data, &y, lambda);
        prev = cur;
        cur = Lr {
            w: y.w.iter().zip(&g).map(|(a, d)| a - eta * d).collect(),
            b: y.b - eta * gb,
        };
    }
    let (loss, _, _) = loss_grad(data, &cur, lambda);
    (cur, loss)
}

/// Training tuples with prereg §1 weights: injections carry half the mass, each benign source
/// an equal share of the other half.
fn weighted<'a>(
    benign_sources: &[Vec<&'a Sparse>],
    inj: &[&'a Sparse],
) -> Vec<(&'a Sparse, f64, f64)> {
    let ns = benign_sources.iter().filter(|s| !s.is_empty()).count() as f64;
    let mut out = Vec::new();
    for src in benign_sources {
        for x in src {
            out.push((*x, 0.0, 0.5 / ns / src.len() as f64));
        }
    }
    for x in inj {
        out.push((*x, 1.0, 0.5 / inj.len() as f64));
    }
    out
}

fn quantile95(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let k = ((0.95 * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1;
    s[k]
}

/// Count `Flagged` refusals when inserting `texts` through the real Enterprise path.
fn flagged_through_insert<S: FnMut(&str) -> f64>(
    guard: ConformalGuard,
    scorer: S,
    texts: &[&str],
) -> usize {
    let ig = IngestGuard::new(guard, scorer).expect("calibrated guard");
    let mut mem = GovernedDocumentMemory::with_guard(|| NoVec, DocRankConfig::default(), ig);
    let tenant = TenantId::new("fpr-v6").unwrap();
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

fn v3_score(text: &str) -> f64 {
    static T: std::sync::OnceLock<HashingTokenizer> = std::sync::OnceLock::new();
    let t = defang(text).0;
    let e = shared_detector().explain(&t);
    let n = T.get_or_init(HashingTokenizer::new).features(&t).len();
    (e.margin as f64 - e.prior_margin as f64) / (n.max(1) as f64)
}

struct Item {
    key: String,
    text: String,
    phi: Sparse,
    norm: String,
}
fn items(v: Vec<(String, String)>) -> Vec<Item> {
    v.into_iter()
        .map(|(key, text)| Item {
            phi: phi(&text),
            norm: norm(&defang(&text).0),
            key,
            text,
        })
        .collect()
}

fn refs<'a>(v: &'a [Item], idx: &[usize]) -> Vec<&'a Sparse> {
    idx.iter().map(|&i| &v[i].phi).collect()
}
fn texts<'a>(v: &'a [Item], idx: &[usize]) -> Vec<&'a str> {
    idx.iter().map(|&i| v[i].text.as_str()).collect()
}

fn rate(k: usize, n: usize) -> serde_json::Value {
    let (lo, hi) = clopper_pearson(k, n);
    serde_json::json!({"k":k,"n":n,"rate":if n>0 {k as f64/n as f64} else {f64::NAN},"cp95_lo":lo,"cp95_hi":hi})
}

fn mean_sd(v: &[f64]) -> (f64, f64) {
    let n = v.len() as f64;
    let m = v.iter().sum::<f64>() / n;
    (
        m,
        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (n - 1.0)).sqrt(),
    )
}

/// Dolly-15k `instruction` fields (benign informal requests), deduplicated by normalised text,
/// excluding any whose normalised text equals a deepset text (either label).
fn load_dolly(path: &str, deepset_norms: &HashSet<String>) -> (Kv, usize, usize, usize) {
    let bytes = std::fs::read(path).expect("read dolly");
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        DOLLY_SHA,
        "dolly SHA mismatch: run invalid"
    );
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    let (mut blank, mut dup, mut ds_overlap) = (0, 0, 0);
    for (row, line) in bytes.lines().enumerate() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let t = v["instruction"].as_str().unwrap_or("").to_string();
        if t.trim().is_empty() {
            blank += 1;
            continue;
        }
        let n = norm(&defang(&t).0);
        if deepset_norms.contains(&n) {
            ds_overlap += 1;
            continue;
        }
        if !seen.insert(n) {
            dup += 1;
            continue;
        }
        out.push((row.to_string(), t));
    }
    (out, blank, dup, ds_overlap)
}

fn fpr_verdict(m: f64, se: f64, alpha: f64, degenerate: bool) -> &'static str {
    if m - T95_9 * se > alpha {
        "REFUTED"
    } else if degenerate {
        "INCONCLUSIVE(degenerate)"
    } else if m <= alpha + DELTA {
        "CONFIRMED"
    } else {
        "INCONCLUSIVE"
    }
}

fn control_verdict(r: &serde_json::Value) -> &'static str {
    if r["cp95_hi"].as_f64().unwrap() <= CHAT_CONTROL_MAX {
        "CONFIRMED"
    } else if r["cp95_lo"].as_f64().unwrap() > CHAT_CONTROL_MAX {
        "REFUTED"
    } else {
        "INCONCLUSIVE"
    }
}

const ARMS: [&str; 4] = ["v6", "v6_pooled", "v5r", "baseline_v3"];

fn pick(v: &[Item], c: &str, seed: u32, rs: &[u8]) -> Vec<usize> {
    (0..v.len())
        .filter(|&i| rs.contains(&(split_hash(c, seed, &v[i].key)[0] % 4)))
        .collect()
}
fn part(v: &[Item], c: &str, seed: u32, idx: &[usize], want_inner: bool) -> Vec<usize> {
    idx.iter()
        .copied()
        .filter(|&i| (split_hash(c, seed, &v[i].key)[1] % 4 == 0) == want_inner)
        .collect()
}
fn zs(m: &Lr, v: &[Item], idx: &[usize]) -> Vec<f64> {
    idx.iter().map(|&i| m.z(&v[i].phi)).collect()
}

/// Fit with λ chosen on the inner split (prereg §1): maximise inner injection TPR at the
/// max over `pools` of the inner benign 95th percentiles.
fn train(
    benign: &[(&[Item], &str, &[usize])],
    pools: &[usize],
    inj: &[Item],
    i_tr: &[usize],
    seed: u32,
) -> (Lr, f64, f64, Vec<serde_json::Value>) {
    let mut best: Option<(f64, f64)> = None;
    let mut sel = Vec::new();
    for &lambda in &LAMBDAS {
        let src: Vec<Vec<&Sparse>> = benign
            .iter()
            .map(|(v, c, idx)| refs(v, &part(v, c, seed, idx, false)))
            .collect();
        let data = weighted(&src, &refs(inj, &part(inj, "ds1", seed, i_tr, false)));
        let (m, loss) = fit(&data, lambda);
        let thr = pools
            .iter()
            .map(|&p| {
                let (v, c, idx) = benign[p];
                quantile95(&zs(&m, v, &part(v, c, seed, idx, true)))
            })
            .fold(f64::NEG_INFINITY, f64::max);
        let iv = part(inj, "ds1", seed, i_tr, true);
        let tpr =
            iv.iter().filter(|&&i| m.z(&inj[i].phi) > thr).count() as f64 / iv.len().max(1) as f64;
        sel.push(serde_json::json!({"lambda":lambda,"inner_tpr":tpr,"inner_thr":thr,"loss":loss}));
        if best.is_none_or(|(bt, _)| tpr >= bt) {
            best = Some((tpr, lambda));
        }
    }
    let lambda = best.unwrap().1;
    let src: Vec<Vec<&Sparse>> = benign.iter().map(|(v, _, idx)| refs(v, idx)).collect();
    let (m, loss) = fit(&weighted(&src, &refs(inj, i_tr)), lambda);
    (m, lambda, loss, sel)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        6,
        "usage: <scifact> <nfcorpus> <fiqa> <deepset.jsonl> <dolly.jsonl> <out-model.json>"
    );
    let model_fp = shared_detector().model().fingerprint();
    assert_eq!(
        model_fp, MODEL_FP,
        "Core model fingerprint mismatch: run invalid"
    );
    let to_kv = |d: Vec<Doc>| d.into_iter().map(|d| (d.id, d.text)).collect::<Vec<_>>();
    let (fiqa, fiqa_blank) = load(&args[2], FIQA_SHA);
    let (sci, sci_blank) = load(&args[0], SCIFACT_SHA);
    let (nfc, nfc_blank) = load(&args[1], NFCORPUS_SHA);
    let (pos, neg, ds_blank, ds_leak) = load_deepset_v5(&args[3]);
    let ds_norms: HashSet<String> = pos
        .iter()
        .chain(neg.iter())
        .map(|(_, t)| norm(&defang(t).0))
        .collect();
    let (dolly, dolly_blank, dolly_dup, dolly_ds) = load_dolly(&args[4], &ds_norms);
    let fiqa = items(to_kv(fiqa));
    let sci = items(to_kv(sci));
    let nfc = items(to_kv(nfc));
    let inj = items(pos);
    let ds0 = items(neg);
    let dolly = items(dolly);
    let ood = items(
        core_injections()
            .into_iter()
            .enumerate()
            .map(|(i, t)| (i.to_string(), t))
            .collect(),
    );
    let fiqa_v3: Vec<f64> = fiqa.iter().map(|d| v3_score(&d.text)).collect();
    println!(
        "{}",
        serde_json::json!({"kind":"meta","core_model_fingerprint":model_fp,
        "fiqa":fiqa.len(),"fiqa_blank":fiqa_blank,"scifact":sci.len(),"scifact_blank":sci_blank,
        "nfcorpus":nfc.len(),"nfcorpus_blank":nfc_blank,"inj":inj.len(),"inj_core_leak_excluded":ds_leak,
        "ds0_control":ds0.len(),"deepset_blank":ds_blank,"dolly":dolly.len(),"dolly_blank":dolly_blank,
        "dolly_dup":dolly_dup,"dolly_deepset_overlap_excluded":dolly_ds,"ood_core_injections":ood.len(),
        "seeds":SEEDS,"iters":ITERS,"lambdas":LAMBDAS,"threads":THREADS,"arms":ARMS})
    );

    // [arm][alpha] -> per-seed values
    let mut f_fiqa = vec![vec![Vec::<f64>::new(); 3]; 4];
    let mut f_dolly = vec![vec![Vec::<f64>::new(); 3]; 4];
    let mut f_ds0 = vec![vec![Vec::<f64>::new(); 3]; 4];
    let mut tprs = vec![vec![Vec::<f64>::new(); 3]; 4];
    let mut seed0: Option<serde_json::Value> = None;
    let mut degenerate: Vec<String> = Vec::new();

    for seed in 0..SEEDS {
        let (f_tr, f_cal, f_te) = (
            pick(&fiqa, "fiqa", seed, &[0, 1]),
            pick(&fiqa, "fiqa", seed, &[2]),
            pick(&fiqa, "fiqa", seed, &[3]),
        );
        let (y_tr, y_cal, y_te) = (
            pick(&dolly, "dolly", seed, &[0, 1]),
            pick(&dolly, "dolly", seed, &[2]),
            pick(&dolly, "dolly", seed, &[3]),
        );
        let (i_tr, i_te) = (
            pick(&inj, "ds1", seed, &[0, 1]),
            pick(&inj, "ds1", seed, &[2, 3]),
        );
        let (s_tr, s_te) = (
            pick(&sci, "scifact", seed, &[0, 1]),
            pick(&sci, "scifact", seed, &[2, 3]),
        );
        for (a, b) in [
            (&f_tr, &f_cal),
            (&f_tr, &f_te),
            (&f_cal, &f_te),
            (&y_tr, &y_cal),
            (&y_tr, &y_te),
            (&y_cal, &y_te),
            (&i_tr, &i_te),
            (&s_tr, &s_te),
        ] {
            let sa: HashSet<&usize> = a.iter().collect();
            assert!(
                b.iter().all(|i| !sa.contains(i)),
                "split overlap: run invalid"
            );
            assert!(!a.is_empty() && !b.is_empty(), "empty split");
        }
        // ---- exact-text leakage exclusion: cal vs train; tests/control/probes vs train ∪ cal
        let nm = |v: &'_ [Item], idx: &[usize]| -> Vec<String> {
            idx.iter().map(|&i| v[i].norm.clone()).collect()
        };
        let mut train_n: HashSet<String> = HashSet::new();
        for x in [
            nm(&fiqa, &f_tr),
            nm(&dolly, &y_tr),
            nm(&sci, &s_tr),
            nm(&inj, &i_tr),
        ] {
            train_n.extend(x);
        }
        let mut leak = serde_json::Map::new();
        let mut clean = |name: &str, v: &[Item], idx: Vec<usize>, ex: &HashSet<String>| {
            let before = idx.len();
            let out: Vec<usize> = idx
                .into_iter()
                .filter(|&i| !ex.contains(&v[i].norm))
                .collect();
            leak.insert(name.into(), (before - out.len()).into());
            out
        };
        let f_cal = clean("fiqa_cal", &fiqa, f_cal, &train_n);
        let y_cal = clean("dolly_cal", &dolly, y_cal, &train_n);
        let mut seen_n = train_n.clone();
        seen_n.extend(nm(&fiqa, &f_cal));
        seen_n.extend(nm(&dolly, &y_cal));
        let f_te = clean("fiqa_test", &fiqa, f_te, &seen_n);
        let y_te = clean("dolly_test", &dolly, y_te, &seen_n);
        let i_te = clean("inj_test", &inj, i_te, &seen_n);
        let d_ctl = clean("ds0_control", &ds0, (0..ds0.len()).collect(), &seen_n);
        let s_te = clean("scifact_probe", &sci, s_te, &seen_n);
        let nfc_all = clean("nfcorpus_probe", &nfc, (0..nfc.len()).collect(), &seen_n);
        let ood_all = clean("ood_inj_probe", &ood, (0..ood.len()).collect(), &seen_n);

        let (m6, l6, loss6, sel6) = train(
            &[
                (&fiqa, "fiqa", &f_tr),
                (&sci, "scifact", &s_tr),
                (&dolly, "dolly", &y_tr),
            ],
            &[0, 2],
            &inj,
            &i_tr,
            seed,
        );
        let (m5, l5, loss5, sel5) = train(
            &[(&fiqa, "fiqa", &f_tr), (&sci, "scifact", &s_tr)],
            &[0],
            &inj,
            &i_tr,
            seed,
        );
        for (name, m, loss) in [("v6", &m6, loss6), ("v5r", &m5, loss5)] {
            if !loss.is_finite() || m.w.iter().any(|v| !v.is_finite()) {
                degenerate.push(format!("f:seed {seed} {name} diverged"));
            }
        }
        if seed == 0 {
            let j = serde_json::json!({"kind":"ingest-fpr-v6-logreg","seed":0,"lambda":l6,"iters":ITERS,
                "dim":m6.w.len(),"feature_map":"log1p+l2 over HashingTokenizer::new() counts on defang(text)",
                "bias":m6.b,"weights":m6.w});
            let s = serde_json::to_string(&j).unwrap();
            std::fs::write(&args[5], &s).expect("write model");
            println!(
                "{}",
                serde_json::json!({"kind":"model_artifact","seed":0,
                "sha256":hex(&Sha256::digest(s.as_bytes())),"path":args[5]})
            );
        }
        println!(
            "{}",
            serde_json::json!({"kind":"train","seed":seed,
            "v6":{"lambda":l6,"loss":loss6,"selection":sel6},"v5r":{"lambda":l5,"loss":loss5,"selection":sel5},
            "n_train":{"fiqa":f_tr.len(),"scifact":s_tr.len(),"dolly":y_tr.len(),"inj":i_tr.len()},
            "n_cal":{"fiqa":f_cal.len(),"dolly":y_cal.len()},
            "n_test":{"fiqa":f_te.len(),"dolly":y_te.len(),"inj":i_te.len(),"ds0_control":d_ctl.len(),
            "scifact":s_te.len(),"nfcorpus":nfc_all.len(),"ood_inj":ood_all.len()},"leakage_excluded":leak})
        );

        let (ft, yt, it, dt) = (
            texts(&fiqa, &f_te),
            texts(&dolly, &y_te),
            texts(&inj, &i_te),
            texts(&ds0, &d_ctl),
        );
        let c6f = zs(&m6, &fiqa, &f_cal);
        let c6y = zs(&m6, &dolly, &y_cal);
        let c6p: Vec<f64> = c6f.iter().chain(c6y.iter()).copied().collect();
        let c5f = zs(&m5, &fiqa, &f_cal);
        let cbf: Vec<f64> = f_cal.iter().map(|&i| fiqa_v3[i]).collect();
        for (ai, &alpha) in ALPHAS.iter().enumerate() {
            for (k, arm) in ARMS.iter().enumerate() {
                let (g, cal): (ConformalGuard, &Vec<f64>) = match k {
                    0 => {
                        let (gf, gy) = (
                            ConformalGuard::calibrate(&c6f, alpha),
                            ConformalGuard::calibrate(&c6y, alpha),
                        );
                        if gf.threshold() >= gy.threshold() {
                            (gf, &c6f)
                        } else {
                            (gy, &c6y)
                        }
                    }
                    1 => (ConformalGuard::calibrate(&c6p, alpha), &c6p),
                    2 => (ConformalGuard::calibrate(&c5f, alpha), &c5f),
                    _ => (ConformalGuard::calibrate(&cbf, alpha), &cbf),
                };
                let sc = |t: &str| match k {
                    0 | 1 => m6.score_text(t),
                    2 => m5.score_text(t),
                    _ => v3_score(t),
                };
                let (kf, ky, ki, kd) = (
                    flagged_through_insert(g, sc, &ft),
                    flagged_through_insert(g, sc, &yt),
                    flagged_through_insert(g, sc, &it),
                    flagged_through_insert(g, sc, &dt),
                );
                let thr = g.threshold();
                let mut rec = serde_json::json!({"kind":"split","arm":arm,"alpha":alpha,"seed":seed,
                    "threshold":thr,"fiqa_test":rate(kf,ft.len()),"dolly_test":rate(ky,yt.len()),
                    "inj_test":rate(ki,it.len()),"ds0_control":rate(kd,dt.len()),
                    "cal_ties_at_threshold":cal.iter().filter(|s| **s == thr).count()});
                f_fiqa[k][ai].push(kf as f64 / ft.len() as f64);
                f_dolly[k][ai].push(ky as f64 / yt.len() as f64);
                f_ds0[k][ai].push(kd as f64 / dt.len() as f64);
                tprs[k][ai].push(ki as f64 / it.len() as f64);
                if seed == 0 && alpha == 0.05 {
                    let (st, nt, ot) = (
                        texts(&sci, &s_te),
                        texts(&nfc, &nfc_all),
                        texts(&ood, &ood_all),
                    );
                    rec["probes"] = serde_json::json!({
                        "scifact":rate(flagged_through_insert(g, sc, &st), st.len()),
                        "nfcorpus":rate(flagged_through_insert(g, sc, &nt), nt.len()),
                        "ood_core_injections":rate(flagged_through_insert(g, sc, &ot), ot.len())});
                    if k == 0 {
                        let mut d = cal.clone();
                        d.sort_by(|a, b| a.total_cmp(b));
                        d.dedup();
                        let maxs = f_te
                            .iter()
                            .map(|&i| m6.z(&fiqa[i].phi))
                            .chain(i_te.iter().map(|&i| m6.z(&inj[i].phi)))
                            .fold(f64::NEG_INFINITY, f64::max);
                        if d.len() < 100 {
                            degenerate.push("a:<100 distinct".into())
                        }
                        if !thr.is_finite() {
                            degenerate.push("b:threshold not finite".into())
                        }
                        if cal.iter().filter(|s| **s == thr).count() as f64
                            > 0.01 * cal.len() as f64
                        {
                            degenerate.push("c:>1% ties".into())
                        }
                        if thr >= maxs {
                            degenerate.push("d:threshold>=max".into())
                        }
                        if kf + ky == 0 {
                            degenerate.push("e:seed-0 FiQA+Dolly test flagged 0".into())
                        }
                        seed0 = Some(
                            serde_json::json!({"tpr":rate(ki,it.len()),"ds0":rate(kd,dt.len())}),
                        );
                    }
                }
                println!("{rec}");
            }
        }
    }

    let n = SEEDS as f64;
    let ms = |v: &[f64]| {
        let (m, sd) = mean_sd(v);
        (m, sd, sd / n.sqrt())
    };
    for (k, arm) in ARMS.iter().enumerate() {
        for (ai, &alpha) in ALPHAS.iter().enumerate() {
            let (mf, sdf, sef) = ms(&f_fiqa[k][ai]);
            let (my, sdy, sey) = ms(&f_dolly[k][ai]);
            let (md, sdd, _) = ms(&f_ds0[k][ai]);
            let (mt, sdt, _) = ms(&tprs[k][ai]);
            let deg = k == 0 && !degenerate.is_empty();
            println!(
                "{}",
                serde_json::json!({"kind":"summary","arm":arm,"alpha":alpha,
                "fiqa_fpr":{"mean":mf,"sd":sdf,"se":sef,"verdict":fpr_verdict(mf,sef,alpha,deg)},
                "dolly_fpr":{"mean":my,"sd":sdy,"se":sey,"verdict":fpr_verdict(my,sey,alpha,deg)},
                "ds0_control_fpr":{"mean":md,"sd":sdd,"min":f_ds0[k][ai].iter().copied().fold(f64::INFINITY,f64::min),
                    "max":f_ds0[k][ai].iter().copied().fold(f64::NEG_INFINITY,f64::max)},
                "inj_tpr":{"mean":mt,"sd":sdt},"primary":k==0&&alpha==0.05,
                "degenerate_reasons":if k==0 {degenerate.clone()} else {vec![]}})
            );
        }
    }
    let s0 = seed0.expect("seed 0");
    let ctl = control_verdict(&s0["ds0"]);
    let (md, _, _) = ms(&f_ds0[0][0]);
    let ctl_ok = ctl == "CONFIRMED" && md <= CHAT_CONTROL_MAX;
    let (mf, _, sef) = ms(&f_fiqa[0][0]);
    let (my, _, sey) = ms(&f_dolly[0][0]);
    let deg = !degenerate.is_empty();
    let fiqa_ok = fpr_verdict(mf, sef, 0.05, deg) == "CONFIRMED";
    let dolly_ok = fpr_verdict(my, sey, 0.05, deg) == "CONFIRMED";
    let nontrivial = s0["tpr"]["cp95_lo"].as_f64().unwrap() > 0.05;
    let (mt6, _, _) = ms(&tprs[0][0]);
    let (mt5, _, _) = ms(&tprs[2][0]);
    let d_ctl: Vec<f64> = (0..SEEDS as usize)
        .map(|s| f_ds0[2][0][s] - f_ds0[0][0][s])
        .collect();
    println!(
        "{}",
        serde_json::json!({"kind":"verdict","alpha":0.05,
        "chat_control_verdict":ctl,"seed0_ds0_control":s0["ds0"],"mean_ds0_control":md,"chat_control_ok":ctl_ok,
        "fiqa_fpr_confirmed":fiqa_ok,"dolly_fpr_confirmed":dolly_ok,
        "detection_verdict":if nontrivial {"NON-TRIVIAL"} else {"TRIVIAL/NEGATIVE"},"seed0_tpr":s0["tpr"],
        "mean_tpr_v6":mt6,"mean_tpr_v5r":mt5,"useful":mt6>=TPR_USEFUL,
        "paired_ds0_reduction_vs_v5r_mean":d_ctl.iter().sum::<f64>()/n,
        "wiring_gate_met":ctl_ok&&fiqa_ok&&dolly_ok&&nontrivial&&mt6>=TPR_USEFUL,
        "superiority_claim":false,"wired":false})
    );
}

//! FPR-v5 harness (prereg `docs/campaigns/2026-10-29-ingest-guard-fpr-v5-prereg.md`).
//!
//! Retrains a research-only L2 logistic-regression injection detector over the Core
//! `HashingTokenizer` features on disjoint train / calibration / test splits, calibrates a
//! `ConformalGuard` on held-out benign FiQA, and compares with the v3 score on the same splits.
//! Core (model, tokenizer, score) is untouched. Research harness only: enables nothing.
//!
//! Usage: `cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v5 -- \
//!         <scifact> <nfcorpus> <fiqa> <deepset-prompt-injections.jsonl> <out-model.json>`

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
const MODEL_FP: &str = "1a21468ef60e681eaffc91bbfa92b94e77d10ca5dd11a5400e9a53586d4dfce8";
const TRAIN_SRC: &str = include_str!("../../../core/examples/train_injection.rs");
const SEEDS: u32 = 10;
const ALPHAS: [f64; 3] = [0.05, 0.01, 0.10];
const LAMBDAS: [f64; 3] = [1e-5, 1e-4, 1e-3];
const ITERS: usize = 400;
const THREADS: usize = 8;
const DELTA: f64 = 0.0025;
const T95_9: f64 = 1.833;
const DS0_CONTROL_MAX: f64 = 0.105;
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
    Sha256::digest(format!("ingest-fpr-v5:{corpus}:{seed}:{key}").as_bytes()).into()
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
    let tenant = TenantId::new("fpr-v5").unwrap();
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        5,
        "usage: <scifact> <nfcorpus> <fiqa> <deepset.jsonl> <out-model.json>"
    );
    let model_fp = shared_detector().model().fingerprint();
    assert_eq!(
        model_fp, MODEL_FP,
        "Core model fingerprint mismatch: run invalid"
    );
    assert_eq!(
        HashingTokenizer::new().dim(),
        shared_detector().model().dim,
        "dim mismatch"
    );

    let to_kv = |d: Vec<Doc>| d.into_iter().map(|d| (d.id, d.text)).collect::<Vec<_>>();
    let (fiqa, fiqa_blank) = load(&args[2], FIQA_SHA);
    let (sci, sci_blank) = load(&args[0], SCIFACT_SHA);
    let (nfc, nfc_blank) = load(&args[1], NFCORPUS_SHA);
    let (pos, neg, ds_blank, ds_leak) = load_deepset_v5(&args[3]);
    let fiqa = items(to_kv(fiqa));
    let sci = items(to_kv(sci));
    let nfc = items(to_kv(nfc));
    let inj = items(pos);
    let ds0 = items(neg);
    let ood = items(
        core_injections()
            .into_iter()
            .enumerate()
            .map(|(i, t)| (i.to_string(), t))
            .collect(),
    );
    let v3 = |v: &[Item]| v.iter().map(|d| v3_score(&d.text)).collect::<Vec<f64>>();
    let fiqa_v3 = v3(&fiqa);
    println!(
        "{}",
        serde_json::json!({"kind":"meta","core_model_fingerprint":model_fp,
        "fiqa":fiqa.len(),"fiqa_blank":fiqa_blank,"scifact":sci.len(),"scifact_blank":sci_blank,
        "nfcorpus":nfc.len(),"nfcorpus_blank":nfc_blank,"inj":inj.len(),"inj_core_leak_excluded":ds_leak,
        "ds0":ds0.len(),"deepset_blank":ds_blank,"ood_core_injections":ood.len(),
        "seeds":SEEDS,"iters":ITERS,"lambdas":LAMBDAS,"threads":THREADS})
    );

    let r_of = |c: &str, s: u32, k: &str| split_hash(c, s, k)[0] % 4;
    let inner = |c: &str, s: u32, k: &str| split_hash(c, s, k)[1] % 4 == 0;
    let mut fpr_v5: Vec<Vec<f64>> = vec![Vec::new(); 3];
    let mut fpr_b: Vec<Vec<f64>> = vec![Vec::new(); 3];
    let (mut tpr_v5, mut tpr_b, mut dtpr) = (Vec::new(), Vec::new(), Vec::new());
    let mut seed0: Option<serde_json::Value> = None;
    let mut degenerate: Vec<String> = Vec::new();

    for seed in 0..SEEDS {
        // ---- splits
        let pick = |v: &'_ [Item], c: &str, rs: &[u8]| -> Vec<usize> {
            (0..v.len())
                .filter(|&i| rs.contains(&r_of(c, seed, &v[i].key)))
                .collect()
        };
        let (f_tr, f_cal, f_te) = (
            pick(&fiqa, "fiqa", &[0, 1]),
            pick(&fiqa, "fiqa", &[2]),
            pick(&fiqa, "fiqa", &[3]),
        );
        let (i_tr, i_te) = (pick(&inj, "ds1", &[0, 1]), pick(&inj, "ds1", &[2, 3]));
        let (d_tr, d_te) = (pick(&ds0, "ds0", &[0, 1]), pick(&ds0, "ds0", &[2, 3]));
        let (s_tr, s_te) = (
            pick(&sci, "scifact", &[0, 1]),
            pick(&sci, "scifact", &[2, 3]),
        );
        for (a, b) in [
            (&f_tr, &f_cal),
            (&f_tr, &f_te),
            (&f_cal, &f_te),
            (&i_tr, &i_te),
            (&d_tr, &d_te),
            (&s_tr, &s_te),
        ] {
            let sa: HashSet<&usize> = a.iter().collect();
            assert!(
                b.iter().all(|i| !sa.contains(i)),
                "split overlap: run invalid"
            );
            assert!(!a.is_empty() && !b.is_empty(), "empty split");
        }
        // ---- exact-text leakage exclusion
        let train_norms: HashSet<&str> = f_tr
            .iter()
            .map(|&i| fiqa[i].norm.as_str())
            .chain(i_tr.iter().map(|&i| inj[i].norm.as_str()))
            .chain(d_tr.iter().map(|&i| ds0[i].norm.as_str()))
            .chain(s_tr.iter().map(|&i| sci[i].norm.as_str()))
            .collect();
        let mut leak = serde_json::Map::new();
        let mut clean = |name: &str, v: &[Item], idx: Vec<usize>| -> Vec<usize> {
            let before = idx.len();
            let out: Vec<usize> = idx
                .into_iter()
                .filter(|&i| !train_norms.contains(v[i].norm.as_str()))
                .collect();
            leak.insert(name.into(), (before - out.len()).into());
            out
        };
        let f_cal = clean("fiqa_cal", &fiqa, f_cal);
        let f_te = clean("fiqa_test", &fiqa, f_te);
        let i_te = clean("inj_test", &inj, i_te);
        let d_te = clean("ds0_control", &ds0, d_te);
        let s_te = clean("scifact_probe", &sci, s_te);
        let nfc_all = clean("nfcorpus_probe", &nfc, (0..nfc.len()).collect());
        let ood_all = clean("ood_inj_probe", &ood, (0..ood.len()).collect());

        // ---- λ selection on inner split of train (prereg §1)
        let part = |v: &'_ [Item], c: &str, idx: &[usize], want_inner: bool| -> Vec<usize> {
            idx.iter()
                .copied()
                .filter(|&i| inner(c, seed, &v[i].key) == want_inner)
                .collect()
        };
        let mut best: Option<(f64, f64)> = None; // (tpr, lambda)
        let mut sel = Vec::new();
        for &lambda in &LAMBDAS {
            let data = weighted(
                &[
                    refs(&fiqa, &part(&fiqa, "fiqa", &f_tr, false)),
                    refs(&sci, &part(&sci, "scifact", &s_tr, false)),
                    refs(&ds0, &part(&ds0, "ds0", &d_tr, false)),
                ],
                &refs(&inj, &part(&inj, "ds1", &i_tr, false)),
            );
            let (m, loss) = fit(&data, lambda);
            let fv: Vec<f64> = part(&fiqa, "fiqa", &f_tr, true)
                .iter()
                .map(|&i| m.z(&fiqa[i].phi))
                .collect();
            let thr = quantile95(&fv);
            let iv: Vec<usize> = part(&inj, "ds1", &i_tr, true);
            let tpr = iv.iter().filter(|&&i| m.z(&inj[i].phi) > thr).count() as f64
                / iv.len().max(1) as f64;
            sel.push(
                serde_json::json!({"lambda":lambda,"inner_tpr":tpr,"inner_thr":thr,"loss":loss,
                "inner_val_fiqa":fv.len(),"inner_val_inj":iv.len()}),
            );
            if best.is_none_or(|(bt, _)| tpr >= bt) {
                best = Some((tpr, lambda));
            }
        }
        let lambda = best.unwrap().1;
        let data = weighted(
            &[refs(&fiqa, &f_tr), refs(&sci, &s_tr), refs(&ds0, &d_tr)],
            &refs(&inj, &i_tr),
        );
        let (model, loss) = fit(&data, lambda);
        if !loss.is_finite() || model.w.iter().any(|v| !v.is_finite()) {
            degenerate.push(format!("f:seed {seed} diverged"));
        }
        if seed == 0 {
            let j = serde_json::json!({"kind":"ingest-fpr-v5-logreg","seed":0,"lambda":lambda,"iters":ITERS,
                "dim":model.w.len(),"feature_map":"log1p+l2 over HashingTokenizer::new() counts on defang(text)",
                "bias":model.b,"weights":model.w});
            let s = serde_json::to_string(&j).unwrap();
            std::fs::write(&args[4], &s).expect("write model");
            println!(
                "{}",
                serde_json::json!({"kind":"model_artifact","seed":0,"sha256":hex(&Sha256::digest(s.as_bytes())),"path":args[4]})
            );
        }
        println!(
            "{}",
            serde_json::json!({"kind":"train","seed":seed,"lambda_selection":sel,"lambda":lambda,
            "final_loss":loss,"n_train":{"fiqa":f_tr.len(),"scifact":s_tr.len(),"ds0":d_tr.len(),"inj":i_tr.len()},
            "n_cal":f_cal.len(),"n_test":{"fiqa":f_te.len(),"inj":i_te.len(),"ds0":d_te.len(),"scifact":s_te.len(),
            "nfcorpus":nfc_all.len(),"ood_inj":ood_all.len()},"leakage_excluded":leak})
        );

        let (ft, it, dt) = (texts(&fiqa, &f_te), texts(&inj, &i_te), texts(&ds0, &d_te));
        let v5_cal: Vec<f64> = f_cal.iter().map(|&i| model.z(&fiqa[i].phi)).collect();
        let b_cal: Vec<f64> = f_cal.iter().map(|&i| fiqa_v3[i]).collect();
        for (ai, &alpha) in ALPHAS.iter().enumerate() {
            for (arm, cal) in [("v5", &v5_cal), ("baseline_v3", &b_cal)] {
                let g = ConformalGuard::calibrate(cal, alpha);
                let sc = |t: &str| {
                    if arm == "v5" {
                        model.score_text(t)
                    } else {
                        v3_score(t)
                    }
                };
                let kf = flagged_through_insert(g, sc, &ft);
                let ki = flagged_through_insert(g, sc, &it);
                let kd = flagged_through_insert(g, sc, &dt);
                let fpr = kf as f64 / ft.len() as f64;
                let tpr = ki as f64 / it.len() as f64;
                let thr = g.threshold();
                let mut rec = serde_json::json!({"kind":"split","arm":arm,"alpha":alpha,"seed":seed,
                    "threshold":thr,"fiqa_test":rate(kf,ft.len()),"inj_test":rate(ki,it.len()),
                    "ds0_control":rate(kd,dt.len()),
                    "cal_ties_at_threshold":cal.iter().filter(|s| **s == thr).count()});
                if arm == "v5" {
                    fpr_v5[ai].push(fpr);
                    if ai == 0 {
                        tpr_v5.push(tpr);
                    }
                } else {
                    fpr_b[ai].push(fpr);
                    if ai == 0 {
                        tpr_b.push(tpr);
                    }
                }
                if seed == 0 && alpha == 0.05 {
                    // probes (seed 0, α = 0.05)
                    let st = texts(&sci, &s_te);
                    let nt = texts(&nfc, &nfc_all);
                    let ot = texts(&ood, &ood_all);
                    rec["probes"] = serde_json::json!({
                        "scifact":rate(flagged_through_insert(g, sc, &st), st.len()),
                        "nfcorpus":rate(flagged_through_insert(g, sc, &nt), nt.len()),
                        "ood_core_injections":rate(flagged_through_insert(g, sc, &ot), ot.len())});
                    if arm == "v5" {
                        let mut d = cal.clone();
                        d.sort_by(|a, b| a.total_cmp(b));
                        d.dedup();
                        let maxs = f_te
                            .iter()
                            .map(|&i| model.z(&fiqa[i].phi))
                            .chain(i_te.iter().map(|&i| model.z(&inj[i].phi)))
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
                        if kf == 0 {
                            degenerate.push("e:seed-0 FiQA-test flagged 0".into())
                        }
                        seed0 = Some(
                            serde_json::json!({"tpr":rate(ki,it.len()),"ds0":rate(kd,dt.len())}),
                        );
                    }
                }
                println!("{rec}");
            }
        }
        dtpr.push(tpr_v5[seed as usize] - tpr_b[seed as usize]);
    }

    let n = SEEDS as f64;
    for (ai, &alpha) in ALPHAS.iter().enumerate() {
        for (arm, f) in [("v5", &fpr_v5[ai]), ("baseline_v3", &fpr_b[ai])] {
            let (m, sd) = mean_sd(f);
            let se = sd / n.sqrt();
            let verdict = if m - T95_9 * se > alpha {
                "REFUTED"
            } else if arm == "v5" && !degenerate.is_empty() {
                "INCONCLUSIVE(degenerate)"
            } else if m <= alpha + DELTA {
                "CONFIRMED"
            } else {
                "INCONCLUSIVE"
            };
            println!(
                "{}",
                serde_json::json!({"kind":"fpr_summary","arm":arm,"alpha":alpha,"mean_fpr":m,
                "sd":sd,"se":se,"strict_m_le_alpha":m<=alpha,"fpr_verdict":verdict,"primary":arm=="v5"&&alpha==0.05,
                "degenerate_reasons":if arm=="v5" {degenerate.clone()} else {vec![]}})
            );
        }
    }
    let s0 = seed0.expect("seed 0");
    let lo = s0["tpr"]["cp95_lo"].as_f64().unwrap();
    let tpr0 = s0["tpr"]["rate"].as_f64().unwrap();
    let ds0r = s0["ds0"]["rate"].as_f64().unwrap();
    let (mv5, _) = mean_sd(&tpr_v5);
    let (mb, _) = mean_sd(&tpr_b);
    let (m5, sd5) = mean_sd(&fpr_v5[0]);
    let fpr_ok =
        (m5 - T95_9 * sd5 / n.sqrt() <= 0.05) && degenerate.is_empty() && m5 <= 0.05 + DELTA;
    let nontrivial = lo > 0.05;
    let ctrl = ds0r <= DS0_CONTROL_MAX;
    println!(
        "{}",
        serde_json::json!({"kind":"verdict","alpha":0.05,
        "detection_verdict":if nontrivial {"NON-TRIVIAL"} else {"TRIVIAL/NEGATIVE"},
        "seed0_tpr":s0["tpr"],"useful_descriptive":tpr0>=0.5,"seed0_ds0_control":s0["ds0"],
        "control_not_exploding":ctrl,"mean_tpr_v5":mv5,"mean_tpr_baseline":mb,
        "paired_delta_tpr_mean":dtpr.iter().sum::<f64>()/n,"seeds_delta_pos":dtpr.iter().filter(|d| **d>0.0).count(),
        "fpr_confirmed":fpr_ok,"wiring_gate_met":fpr_ok&&nontrivial&&ctrl&&mv5>mb,
        "superiority_claim":false,"wired":false})
    );
}

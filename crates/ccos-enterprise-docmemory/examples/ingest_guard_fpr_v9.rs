//! FPR-v9 harness (prereg `docs/campaigns/2026-10-30-ingest-guard-fpr-v9-prereg.md`).
#![allow(clippy::needless_range_loop)]
//!
//! v7 code path (hash φ = log1p+L2 over `HashingTokenizer::new()` counts, L2 logistic regression,
//! max-of-pools conformal threshold), **no MiniLM**, with the benign train/λ/calibration pools
//! expanded by a fourth short-query source `nq_short` (NQ-open train questions). deepset label 0
//! stays an untouched control (never trained, λ-selected or calibrated on).
//! Arms: `v9` (primary), `v7` (sanity, three chat sources), `v9_and` (refuse iff baseline_v3 AND
//! v9 refuse; descriptive), `baseline_v3`. Core untouched. Research harness only: enables nothing.
//!
//! Usage: `cargo run --release -p ccos-enterprise-docmemory --example ingest_guard_fpr_v9 -- \
//!         <scifact> <nfcorpus> <fiqa> <deepset-prompt-injections.jsonl> <chat_v9.jsonl> <out-model.json>`

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
const CHAT_SHA: &str = "aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882";
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
    // Shared corpora keep the v7 split hash (paired with v7/v8 per seed); the new source gets v9.
    let tag = if corpus == "nq_short" {
        "ingest-fpr-v9"
    } else {
        "ingest-fpr-v7"
    };
    Sha256::digest(format!("{tag}:{corpus}:{seed}:{key}").as_bytes()).into()
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
    let tenant = TenantId::new("fpr-v9").unwrap();
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

const CHAT_SOURCES: [&str; 4] = ["dolly", "oasst1", "hh_helpful", "nq_short"];
/// Sources gating P3 (in-pool chat FPR); `nq_short` in-pool FPR is reported descriptively.
const P3_SOURCES: usize = 3;
/// Arms: 0 = v9 (primary), 1 = v7 (sanity), 2 = v9_and, 3 = baseline_v3.
const ARMS: [&str; 4] = ["v9", "v7", "v9_and", "baseline_v3"];

/// Benign negatives built by `docs/campaigns/2026-10-30-ingest-guard-fpr-v9/build_chat_v9.py`;
/// drops any text whose normalised form equals a deepset text (either label).
fn load_chat(path: &str, deepset_norms: &HashSet<String>) -> (Vec<Kv>, Vec<usize>) {
    let bytes = std::fs::read(path).expect("read chat");
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        CHAT_SHA,
        "chat SHA mismatch: run invalid"
    );
    let mut out: Vec<Kv> = vec![Vec::new(); CHAT_SOURCES.len()];
    let mut excl = vec![0usize; CHAT_SOURCES.len()];
    for line in bytes.lines() {
        let v: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let s = CHAT_SOURCES
            .iter()
            .position(|c| *c == v["source"].as_str().unwrap())
            .expect("known source");
        let t = v["text"].as_str().unwrap().to_string();
        if t.trim().is_empty() || deepset_norms.contains(&norm(&defang(&t).0)) {
            excl[s] += 1;
            continue;
        }
        out[s].push((v["key"].as_str().unwrap().to_string(), t));
    }
    (out, excl)
}

struct Acc {
    fiqa: Vec<f64>,
    ds0: Vec<f64>,
    tpr: Vec<f64>,
    chat: Vec<Vec<f64>>, // per chat source test FPR (nq_short is out-of-pool for v7)
}
impl Acc {
    fn new() -> Self {
        Acc {
            fiqa: vec![],
            ds0: vec![],
            tpr: vec![],
            chat: vec![vec![]; CHAT_SOURCES.len()],
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        6,
        "usage: <scifact> <nfcorpus> <fiqa> <deepset.jsonl> <chat_v9.jsonl> <out-model.json>"
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
    let (chat_kv, chat_excl) = load_chat(&args[4], &ds_norms);
    let fiqa = items(to_kv(fiqa));
    let sci = items(to_kv(sci));
    let nfc = items(to_kv(nfc));
    let inj = items(pos);
    let ds0 = items(neg);
    let chat: Vec<Vec<Item>> = chat_kv.into_iter().map(items).collect();
    let ood = items(
        core_injections()
            .into_iter()
            .enumerate()
            .map(|(i, t)| (i.to_string(), t))
            .collect(),
    );
    let fiqa_v3: Vec<f64> = fiqa.iter().map(|d| v3_score(&d.text)).collect();
    let nc = CHAT_SOURCES.len();
    let arm_names: Vec<String> = ARMS.iter().map(|a| a.to_string()).collect();
    println!(
        "{}",
        serde_json::json!({"kind":"meta","core_model_fingerprint":model_fp,
        "fiqa":fiqa.len(),"fiqa_blank":fiqa_blank,"scifact":sci.len(),"scifact_blank":sci_blank,
        "nfcorpus":nfc.len(),"nfcorpus_blank":nfc_blank,"inj":inj.len(),"inj_core_leak_excluded":ds_leak,
        "ds0_control":ds0.len(),"deepset_blank":ds_blank,"chat_sources":CHAT_SOURCES,
        "chat_sizes":chat.iter().map(Vec::len).collect::<Vec<_>>(),"chat_excluded_deepset_overlap_or_blank":chat_excl,
        "ood_core_injections":ood.len(),"seeds":SEEDS,"iters":ITERS,"lambdas":LAMBDAS,"threads":THREADS,"arms":arm_names})
    );
    let mut acc: Vec<Vec<Acc>> = (0..arm_names.len())
        .map(|_| (0..3).map(|_| Acc::new()).collect())
        .collect();
    let mut seed0: Option<serde_json::Value> = None;
    let mut degenerate: Vec<String> = Vec::new();

    for seed in 0..SEEDS {
        let (f_tr, f_cal, f_te) = (
            pick(&fiqa, "fiqa", seed, &[0, 1]),
            pick(&fiqa, "fiqa", seed, &[2]),
            pick(&fiqa, "fiqa", seed, &[3]),
        );
        let c_tr: Vec<Vec<usize>> = (0..nc)
            .map(|c| pick(&chat[c], CHAT_SOURCES[c], seed, &[0, 1]))
            .collect();
        let c_cal: Vec<Vec<usize>> = (0..nc)
            .map(|c| pick(&chat[c], CHAT_SOURCES[c], seed, &[2]))
            .collect();
        let c_te: Vec<Vec<usize>> = (0..nc)
            .map(|c| pick(&chat[c], CHAT_SOURCES[c], seed, &[3]))
            .collect();
        let (i_tr, i_te) = (
            pick(&inj, "ds1", seed, &[0, 1]),
            pick(&inj, "ds1", seed, &[2, 3]),
        );
        let (s_tr, s_te) = (
            pick(&sci, "scifact", seed, &[0, 1]),
            pick(&sci, "scifact", seed, &[2, 3]),
        );
        let mut pairs: Vec<(&Vec<usize>, &Vec<usize>)> = vec![
            (&f_tr, &f_cal),
            (&f_tr, &f_te),
            (&f_cal, &f_te),
            (&i_tr, &i_te),
            (&s_tr, &s_te),
        ];
        for c in 0..nc {
            pairs.extend([
                (&c_tr[c], &c_cal[c]),
                (&c_tr[c], &c_te[c]),
                (&c_cal[c], &c_te[c]),
            ]);
        }
        for (a, b) in pairs {
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
        train_n.extend(nm(&fiqa, &f_tr));
        train_n.extend(nm(&sci, &s_tr));
        train_n.extend(nm(&inj, &i_tr));
        for c in 0..nc {
            train_n.extend(nm(&chat[c], &c_tr[c]));
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
        let c_cal: Vec<Vec<usize>> = c_cal
            .into_iter()
            .enumerate()
            .map(|(c, idx)| clean(&format!("{}_cal", CHAT_SOURCES[c]), &chat[c], idx, &train_n))
            .collect();
        let mut seen_n = train_n.clone();
        seen_n.extend(nm(&fiqa, &f_cal));
        for c in 0..nc {
            seen_n.extend(nm(&chat[c], &c_cal[c]));
        }
        let f_te = clean("fiqa_test", &fiqa, f_te, &seen_n);
        let c_te: Vec<Vec<usize>> = c_te
            .into_iter()
            .enumerate()
            .map(|(c, idx)| clean(&format!("{}_test", CHAT_SOURCES[c]), &chat[c], idx, &seen_n))
            .collect();
        let i_te = clean("inj_test", &inj, i_te, &seen_n);
        let d_ctl = clean("ds0_control", &ds0, (0..ds0.len()).collect(), &seen_n);
        let s_te = clean("scifact_probe", &sci, s_te, &seen_n);
        let nfc_all = clean("nfcorpus_probe", &nfc, (0..nfc.len()).collect(), &seen_n);
        let ood_all = clean("ood_inj_probe", &ood, (0..ood.len()).collect(), &seen_n);

        let (ft, it, dt) = (texts(&fiqa, &f_te), texts(&inj, &i_te), texts(&ds0, &d_ctl));
        let ct: Vec<Vec<&str>> = (0..nc).map(|c| texts(&chat[c], &c_te[c])).collect();
        let mut train_log = serde_json::Map::new();

        // models: 0 = v9 (all four sources), 1 = v7 (three chat sources, sanity)
        let mut models: Vec<Lr> = Vec::new();
        for a in 0..2 {
            let keep: Vec<usize> = (0..if a == 0 { nc } else { P3_SOURCES }).collect();
            let mut benign: Vec<(&[Item], &str, &[usize])> =
                vec![(&fiqa, "fiqa", &f_tr), (&sci, "scifact", &s_tr)];
            for &c in &keep {
                benign.push((&chat[c], CHAT_SOURCES[c], &c_tr[c]));
            }
            let pools: Vec<usize> = std::iter::once(0)
                .chain((0..keep.len()).map(|j| 2 + j))
                .collect();
            let (m, lambda, loss, sel) = train(&benign, &pools, &inj, &i_tr, seed);
            if !loss.is_finite() || m.w.iter().any(|v| !v.is_finite()) {
                degenerate.push(format!("f:seed {seed} {} diverged", arm_names[a]));
            }
            train_log.insert(
                arm_names[a].clone(),
                serde_json::json!({"lambda":lambda,"loss":loss,"selection":sel}),
            );
            models.push(m);
        }
        if seed == 0 {
            let j = serde_json::json!({"kind":"ingest-fpr-v9-logreg","seed":0,"iters":ITERS,
                "lambda":train_log["v9"]["lambda"],"dim":models[0].w.len(),
                "feature_map":"log1p+l2 over HashingTokenizer::new() counts on defang(text)",
                "bias":models[0].b,"weights":models[0].w});
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
            serde_json::json!({"kind":"train","seed":seed,"arms":train_log,
            "n_train":{"fiqa":f_tr.len(),"scifact":s_tr.len(),"inj":i_tr.len(),"chat":c_tr.iter().map(Vec::len).collect::<Vec<_>>()},
            "n_cal":{"fiqa":f_cal.len(),"chat":c_cal.iter().map(Vec::len).collect::<Vec<_>>()},
            "n_test":{"fiqa":f_te.len(),"chat":c_te.iter().map(Vec::len).collect::<Vec<_>>(),"inj":i_te.len(),
            "ds0_control":d_ctl.len(),"scifact":s_te.len(),"nfcorpus":nfc_all.len(),"ood_inj":ood_all.len()},
            "leakage_excluded":leak})
        );

        let cal_f: Vec<Vec<f64>> = models.iter().map(|m| zs(m, &fiqa, &f_cal)).collect();
        let cal_c: Vec<Vec<Vec<f64>>> = models
            .iter()
            .map(|m| (0..nc).map(|c| zs(m, &chat[c], &c_cal[c])).collect())
            .collect();
        let cbf: Vec<f64> = f_cal.iter().map(|&i| fiqa_v3[i]).collect();
        // AND arm: combined score min(z_v9 − thr_v9, v3 − thr_v3) > 0 ⇔ both guards flag; guard
        // threshold 0 comes from calibrating on a constant-zero sample (strict `>` rule).
        let zeros = vec![0.0f64; 1000];
        for (ai, &alpha) in ALPHAS.iter().enumerate() {
            let model_guard = |k: usize| -> (ConformalGuard, &Vec<f64>) {
                let mut best = (ConformalGuard::calibrate(&cal_f[k], alpha), &cal_f[k]);
                let pools = if k == 0 { nc } else { P3_SOURCES };
                for c in 0..pools {
                    let g = ConformalGuard::calibrate(&cal_c[k][c], alpha);
                    if g.threshold() > best.0.threshold() {
                        best = (g, &cal_c[k][c]);
                    }
                }
                best
            };
            let g3 = ConformalGuard::calibrate(&cbf, alpha);
            let (g9, _) = model_guard(0);
            let (t9, t3) = (g9.threshold(), g3.threshold());
            for (k, arm) in arm_names.iter().enumerate() {
                let (g, cal): (ConformalGuard, &Vec<f64>) = match k {
                    0 | 1 => model_guard(k),
                    2 => (ConformalGuard::calibrate(&zeros, alpha), &zeros),
                    _ => (g3, &cbf),
                };
                let sc = |t: &str| match k {
                    0 | 1 => models[k].score_text(t),
                    2 => (models[0].score_text(t) - t9).min(v3_score(t) - t3),
                    _ => v3_score(t),
                };
                let (kf, ki, kd) = (
                    flagged_through_insert(g, sc, &ft),
                    flagged_through_insert(g, sc, &it),
                    flagged_through_insert(g, sc, &dt),
                );
                let kc: Vec<usize> = ct
                    .iter()
                    .map(|t| flagged_through_insert(g, sc, t))
                    .collect();
                let thr = g.threshold();
                let chat_rates: serde_json::Map<String, serde_json::Value> = (0..nc)
                    .map(|c| (CHAT_SOURCES[c].to_string(), rate(kc[c], ct[c].len())))
                    .collect();
                let mut rec = serde_json::json!({"kind":"split","arm":arm,"alpha":alpha,"seed":seed,
                    "threshold":thr,"fiqa_test":rate(kf,ft.len()),"chat_test":chat_rates,
                    "inj_test":rate(ki,it.len()),"ds0_control":rate(kd,dt.len()),
                    "cal_ties_at_threshold":cal.iter().filter(|s| **s == thr).count()});
                let a = &mut acc[k][ai];
                a.fiqa.push(kf as f64 / ft.len() as f64);
                a.ds0.push(kd as f64 / dt.len() as f64);
                a.tpr.push(ki as f64 / it.len() as f64);
                for c in 0..nc {
                    a.chat[c].push(kc[c] as f64 / ct[c].len() as f64);
                }
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
                            .map(|&i| models[0].z(&fiqa[i].phi))
                            .chain(i_te.iter().map(|&i| models[0].z(&inj[i].phi)))
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
                        if kf + kc.iter().sum::<usize>() == 0 {
                            degenerate.push("e:seed-0 benign tests flagged 0".into())
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
    let deg = !degenerate.is_empty();
    let mut chat_ok_v9 = true;
    let mut descriptive = serde_json::Map::new();
    for (k, arm) in arm_names.iter().enumerate() {
        for (ai, &alpha) in ALPHAS.iter().enumerate() {
            let a = &acc[k][ai];
            let (mf, sdf, sef) = ms(&a.fiqa);
            let (md, sdd, _) = ms(&a.ds0);
            let (mt, sdt, _) = ms(&a.tpr);
            let mut chat_s = serde_json::Map::new();
            for c in 0..nc {
                let (m, sd, se) = ms(&a.chat[c]);
                let in_pool = (k == 0) || (k == 1 && c < P3_SOURCES);
                let v = fpr_verdict(m, se, alpha, k == 0 && deg);
                if k == 0 && ai == 0 && c < P3_SOURCES && v != "CONFIRMED" {
                    chat_ok_v9 = false;
                }
                if k == 0 && ai == 0 && c >= P3_SOURCES {
                    descriptive.insert(
                        CHAT_SOURCES[c].into(),
                        serde_json::json!({"mean":m,"se":se,"verdict":v}),
                    );
                }
                chat_s.insert(
                    CHAT_SOURCES[c].into(),
                    serde_json::json!({"mean":m,"sd":sd,"se":se,"in_calibration_pool":in_pool,"gating":k==0&&c<P3_SOURCES,"verdict":v}),
                );
            }
            println!(
                "{}",
                serde_json::json!({"kind":"summary","arm":arm,"alpha":alpha,
                "fiqa_fpr":{"mean":mf,"sd":sdf,"se":sef,"verdict":fpr_verdict(mf,sef,alpha,k==0&&deg)},
                "chat_fpr":chat_s,
                "ds0_control_fpr":{"mean":md,"sd":sdd,"min":a.ds0.iter().copied().fold(f64::INFINITY,f64::min),
                    "max":a.ds0.iter().copied().fold(f64::NEG_INFINITY,f64::max)},
                "inj_tpr":{"mean":mt,"sd":sdt},"primary":k==0&&alpha==0.05,"gating":k==0,
                "degenerate_reasons":if k==0 {degenerate.clone()} else {vec![]}})
            );
        }
    }
    let s0 = seed0.expect("seed 0");
    let ctl = control_verdict(&s0["ds0"]);
    let (md, _, _) = ms(&acc[0][0].ds0);
    let ctl_ok = ctl == "CONFIRMED" && md <= CHAT_CONTROL_MAX;
    let (mf, _, sef) = ms(&acc[0][0].fiqa);
    let fiqa_ok = fpr_verdict(mf, sef, 0.05, deg) == "CONFIRMED";
    let nontrivial = s0["tpr"]["cp95_lo"].as_f64().unwrap() > 0.05;
    let (mt, _, _) = ms(&acc[0][0].tpr);
    println!(
        "{}",
        serde_json::json!({"kind":"verdict","alpha":0.05,
        "chat_control_verdict":ctl,"seed0_ds0_control":s0["ds0"],"mean_ds0_control":md,"chat_control_ok":ctl_ok,
        "fiqa_fpr_confirmed":fiqa_ok,"in_pool_chat_fpr_confirmed":chat_ok_v9,
        "nq_short_in_pool_fpr_descriptive":descriptive,
        "detection_verdict":if nontrivial {"NON-TRIVIAL"} else {"TRIVIAL/NEGATIVE"},"seed0_tpr":s0["tpr"],
        "mean_tpr_v9":mt,"useful":mt>=TPR_USEFUL,
        "wiring_gate_met":ctl_ok&&fiqa_ok&&chat_ok_v9&&nontrivial&&mt>=TPR_USEFUL,
        "superiority_claim":false,"wired":false})
    );
}

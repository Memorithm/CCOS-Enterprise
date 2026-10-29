//! # SML-GROK-ICM-5 PR3 campaign harness — `sml-grok-icm-concurrent` (sigpage-v0) vs BM25.
//!
//! Prereg: SML-GENIUS `docs/SML-GROK-ICM-5-DOCUMENT-RANKING-PREREGISTRATION.md` (#761, `6fe51bee`).
//! Frozen run: strict BEIR import (unchanged CCOS importer, no blank-doc policy), BM25(1.2,0.75)
//! from `ccos_core::retrieval` (reference of the CCOS #217 harness), `sml_core::icm_rank::
//! SignaturePageRanker` with signature seeds {0,1,2}, depth 100, nDCG@10 / R@100 / MRR@10, paired
//! percentile bootstrap (10 000 resamples, seed 20261029) of Δ nDCG@10 per signature seed.
//! No tuning: sigpage-v0 is used exactly as merged in SML #762. Deterministic stdout; timings on
//! stderr; no query dropped (a query the ranker rejects scores an empty ranking and is counted).
//!
//! Optional 2nd arg: a published CCOS `beir_campaign_v3` stdout. Its per-query `bm25` column must
//! equal ours bit-for-bit (sanity, else abort) and its `docmem_fused_minilm` column is used as
//! the paired H2 baseline (not re-encoded here).
//!
//! ```bash
//! cargo run --release -p ccos-enterprise-sml-retrieval --features sml-backend \
//!   --example beir_sml_icm5 -- <beir-dir> [published-v3-stdout]
//! ```

#[path = "../../../core/examples/support/beir_import.rs"]
mod beir_import;

use beir_import::{load_dataset, BeirDataset};
use ccos_core::retrieval::{metrics, Bm25Index};
use sml_core::icm_rank::{
    DocumentRanker, RankError, SignaturePageRanker, ValidationStatus, ARM_ID,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

const DEPTH: usize = 100;
const BOOT: usize = 10_000;
const BOOT_SEED: u64 = 20_261_029;
const SIG_SEEDS: [u64; 3] = [0, 1, 2];

fn main() {
    if let Err(e) = run() {
        eprintln!("beir_sml_icm5: {e}");
        std::process::exit(1);
    }
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

fn paired_ci(diff: &[f64]) -> (f64, f64) {
    let n = diff.len();
    let mut s = BOOT_SEED.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut means: Vec<f64> = (0..BOOT)
        .map(|_| {
            (0..n)
                .map(|_| diff[(xorshift(&mut s) % n as u64) as usize])
                .sum::<f64>()
                / n as f64
        })
        .collect();
    means.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (
        means[(BOOT as f64 * 0.025) as usize],
        means[(BOOT as f64 * 0.975) as usize],
    )
}

/// Zero-padded decimal id so that the ranker's `id asc` tie-break equals corpus order.
fn sid(i: usize) -> String {
    format!("{i:010}")
}

fn published(path: &str) -> Result<HashMap<String, (f64, f64)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut lines = text.lines();
    let header = lines.next().ok_or("empty published stdout")?;
    let cols: Vec<&str> = header
        .trim_start_matches("# per_query: ")
        .split('\t')
        .collect();
    let bi = cols
        .iter()
        .position(|c| *c == "bm25")
        .ok_or("no bm25 column")?;
    let fi = cols
        .iter()
        .position(|c| *c == "docmem_fused_minilm")
        .ok_or("no fused column")?;
    let mut out = HashMap::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let f: Vec<&str> = l.split('\t').collect();
        let p = |i: usize| f[i].parse::<f64>().map_err(|e| e.to_string());
        out.insert(f[0].to_string(), (p(bi)?, p(fi)?));
    }
    Ok(out)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .ok_or("usage: beir_sml_icm5 <beir-dir> [published-v3-stdout]")?;
    let pubd = args.get(1).map(|p| published(p)).transpose()?;
    let BeirDataset {
        docs,
        queries,
        qrels,
        qrel_stats,
    } = load_dataset(Path::new(dir))?;
    eprintln!(
        "strict import: qrel_rows={} positive={}",
        qrel_stats.data_rows, qrel_stats.positive_rows
    );
    let mut qids: Vec<&String> = qrels.keys().collect();
    qids.sort();

    let t = Instant::now();
    let mut bm25 = Bm25Index::new(1.2, 0.75);
    let mut sml: Vec<SignaturePageRanker> = SIG_SEEDS
        .iter()
        .map(|s| SignaturePageRanker::new(*s))
        .collect();
    for (i, d) in docs.iter().enumerate() {
        bm25.add(i as u64, d);
        for r in &mut sml {
            r.insert(&sid(i), d).map_err(|e| e.to_string())?;
        }
    }
    eprintln!("indexes: {:.1?}", t.elapsed());

    let mut names = vec!["bm25".to_string()];
    names.extend(SIG_SEEDS.iter().map(|s| format!("{ARM_ID}_seed{s}")));
    if pubd.is_some() {
        names.push("docmem_fused_minilm(published)".into());
    }
    let mut per: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut agg = vec![[0.0f64; 2]; names.len()];
    let mut rejected = vec![0usize; SIG_SEEDS.len()];
    let t = Instant::now();
    println!("# per_query: qid\t{}", names.join("\t"));
    for qid in &qids {
        let q = &queries[*qid];
        let gains = &qrels[*qid];
        let relevant: HashSet<u64> = gains.keys().copied().collect();
        let mut ranks = vec![bm25
            .search(q, DEPTH)
            .into_iter()
            .map(|s| s.id)
            .collect::<Vec<u64>>()];
        for (k, r) in sml.iter_mut().enumerate() {
            match r.rank(q, DEPTH) {
                Ok(list) => {
                    if list.arm_id != ARM_ID || list.status != ValidationStatus::NotBeirValidated {
                        return Err("unexpected arm/status".into());
                    }
                    ranks.push(
                        list.candidates
                            .iter()
                            .map(|c| c.id.parse::<u64>().unwrap())
                            .collect(),
                    );
                }
                Err(RankError::EmptyQuery) => {
                    rejected[k] += 1;
                    ranks.push(Vec::new());
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let mut row = qid.to_string();
        for (k, rank) in ranks.iter().enumerate() {
            let nd = metrics::ndcg_at_k(rank, gains, 10);
            per[k].push(nd);
            agg[k][0] += metrics::recall_at_k(rank, &relevant, 100);
            agg[k][1] += metrics::reciprocal_rank(&rank[..rank.len().min(10)], &relevant);
            row.push_str(&format!("\t{nd:.6}"));
        }
        if let Some(p) = &pubd {
            let (pb, pf) = *p
                .get(*qid)
                .ok_or(format!("qid {qid} missing in published stdout"))?;
            if format!("{pb:.6}") != format!("{:.6}", per[0].last().unwrap()) {
                return Err(format!("bm25 mismatch vs published on qid {qid}"));
            }
            let k = names.len() - 1;
            per[k].push(pf);
            row.push_str(&format!("\t{pf:.6}"));
        }
        println!("{row}");
    }
    eprintln!("retrieve+score: {:.1?}", t.elapsed());
    let n = qids.len() as f64;
    println!(
        "\n# summary docs={} judged_queries={} sml_rejected_queries={:?}",
        docs.len(),
        qids.len(),
        rejected
    );
    println!("arm\tnDCG@10\tR@100\tMRR@10");
    for (k, name) in names.iter().enumerate() {
        let m = per[k].iter().sum::<f64>() / n;
        if pubd.is_some() && k == names.len() - 1 {
            println!("{name}\t{m:.4}\t-\t-");
        } else {
            println!("{name}\t{m:.4}\t{:.4}\t{:.4}", agg[k][0] / n, agg[k][1] / n);
        }
    }
    let mut baselines = vec![(0usize, "bm25")];
    if pubd.is_some() {
        baselines.push((names.len() - 1, "docmem_fused_minilm"));
    }
    for (b, bname) in baselines {
        println!("\n# paired nDCG@10 delta (sml - {bname}), 95% percentile bootstrap ({BOOT} resamples, seed {BOOT_SEED})");
        for k in 1..=SIG_SEEDS.len() {
            let diff: Vec<f64> = per[k].iter().zip(&per[b]).map(|(a, c)| a - c).collect();
            let mean = diff.iter().sum::<f64>() / n;
            let wins = diff.iter().filter(|d| **d > 0.0).count();
            let losses = diff.iter().filter(|d| **d < 0.0).count();
            let (lo, hi) = paired_ci(&diff);
            println!(
                "{}\tdelta={mean:+.4}\twins={wins}\tlosses={losses}\tci95=[{lo:+.4},{hi:+.4}]",
                names[k]
            );
        }
    }
    println!("\nstatus: NotBeirValidated (input) ; superiority_claim: false");
    Ok(())
}

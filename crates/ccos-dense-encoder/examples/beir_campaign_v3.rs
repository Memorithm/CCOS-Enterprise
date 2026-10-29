//! # BEIR campaign v3 — `DocumentMemory` with a real dense encoder (all-MiniLM-L6-v2) vs BM25.
//!
//! Prereg: `docs/campaigns/2026-10-28-beir-v3-prereg.md`. `--grid` scans the fusion weight on the
//! **train** qrels only (a directory whose `qrels/test.tsv` is the train split). The default mode
//! runs the frozen arms on the given split, prints per-query nDCG@10, summaries and paired
//! bootstrap intervals against BM25. Deterministic stdout; timings on stderr; no query dropped.
//!
//! ```bash
//! cargo run --release -p ccos-dense-encoder --example beir_campaign_v3 -- <beir-dir> <model-dir> [--grid]
//! ```

#[path = "../../../core/examples/support/beir_import.rs"]
mod beir_import;

use beir_import::{load_dataset_with, BeirDataset, BlankDocPolicy};
use ccos_core::doc_memory::{DocRankConfig, DocumentMemory, PrfConfig, RankMode};
use ccos_core::retrieval::{metrics, reciprocal_rank_fusion, Bm25Index, Encoder, Scored};
use ccos_dense_encoder::{BertSentenceEncoder, CachedEncoder, DEFAULT_MAX_LEN, DEFAULT_THREADS};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

const DEPTH: usize = 100;
const BOOT: usize = 10_000;
const SEEDS: [u64; 3] = [1, 2, 3];
const POOL: usize = 100;
/// Train-grid values for the fusion weight (prereg).
const GRID_ALPHA: [f32; 9] = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9];

/// v2 PRF config, carried over unchanged (frozen from NFCorpus train in v2).
const FROZEN_PRF: PrfConfig = PrfConfig {
    fb_docs: 5,
    fb_terms: 20,
    orig_weight: 0.3,
    max_df_ratio: 0.05,
};
/// Frozen from the SciFact train grid (see prereg). Changing it after the prereg voids the run.
const FROZEN_ALPHA: f32 = 0.5;

fn main() {
    if let Err(e) = run() {
        eprintln!("beir_campaign_v3: {e}");
        std::process::exit(1);
    }
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

fn paired_ci(diff: &[f64], seed: u64) -> (f64, f64) {
    let n = diff.len();
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
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

fn ids(v: Vec<Scored>) -> Vec<u64> {
    v.into_iter().map(|s| s.id).collect()
}

fn build<E: Encoder>(enc: E, docs: &[String], cfg: DocRankConfig) -> DocumentMemory<E> {
    let mut m = DocumentMemory::new(enc, cfg);
    for (i, d) in docs.iter().enumerate() {
        m.upsert(i as u64, d);
    }
    m
}

fn cfg(mode: RankMode, prf: Option<PrfConfig>) -> DocRankConfig {
    DocRankConfig {
        mode,
        prf,
        ..Default::default()
    }
}

fn run() -> Result<(), String> {
    let usage = "usage: beir_campaign_v3 <beir-dir> <model-dir> [--grid] [--skip-blank-docs]";
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Prereg v5 amendment: opt-in blank-document policy; default stays strict (fail).
    let policy = if let Some(i) = args.iter().position(|a| a == "--skip-blank-docs") {
        args.remove(i);
        BlankDocPolicy::SkipUnretrievable
    } else {
        BlankDocPolicy::Fail
    };
    let dir = args.first().ok_or(usage)?;
    let model_dir = args.get(1).ok_or(usage)?;
    let grid = match args.get(2).map(String::as_str) {
        Some("--grid") => true,
        None => false,
        _ => return Err(usage.into()),
    };
    if !grid && FROZEN_ALPHA.is_nan() {
        return Err("FROZEN_ALPHA not set: run --grid on train and freeze it first".into());
    }
    let BeirDataset {
        docs,
        skipped_blank_docs,
        queries,
        qrels,
        qrel_stats,
    } = load_dataset_with(Path::new(dir), policy)?;
    eprintln!(
        "strict import: qrel_rows={} positive={} skipped_blank_docs={}",
        qrel_stats.data_rows, qrel_stats.positive_rows, skipped_blank_docs
    );
    let mut qids: Vec<&String> = qrels.keys().collect();
    qids.sort();

    let t = Instant::now();
    let bert = BertSentenceEncoder::load(Path::new(model_dir), DEFAULT_MAX_LEN, DEFAULT_THREADS)
        .map_err(|e| e.to_string())?;
    let mut enc = CachedEncoder::new(bert);
    enc.encode_batch(&docs);
    let qtexts: Vec<String> = qids.iter().map(|q| queries[*q].clone()).collect();
    enc.encode_batch(&qtexts);
    eprintln!(
        "encoded {} texts (dim={}): {:.1?}",
        enc.cached(),
        enc.embedding_dim(),
        t.elapsed()
    );

    if grid {
        println!("config\tnDCG@10");
        let mut configs: Vec<(String, DocRankConfig)> = vec![
            ("lexical".into(), cfg(RankMode::Lexical, None)),
            ("dense_minilm".into(), cfg(RankMode::Dense, None)),
        ];
        for alpha in GRID_ALPHA {
            configs.push((
                format!("fused_minilm a={alpha}"),
                cfg(RankMode::Fused { alpha, pool: POOL }, None),
            ));
        }
        for (name, c) in configs {
            let mut m = build(enc.clone(), &docs, c);
            let s: f64 = qids
                .iter()
                .map(|q| metrics::ndcg_at_k(&ids(m.rank(&queries[*q], DEPTH)), &qrels[*q], 10))
                .sum();
            println!("{name}\t{:.4}", s / qids.len() as f64);
        }
        return Ok(());
    }

    let t = Instant::now();
    let mut bm25 = Bm25Index::new(1.2, 0.75);
    for (i, d) in docs.iter().enumerate() {
        bm25.add(i as u64, d);
    }
    let fused = RankMode::Fused {
        alpha: FROZEN_ALPHA,
        pool: POOL,
    };
    let mut dm_lex = build(enc.clone(), &docs, cfg(RankMode::Lexical, None));
    let mut dm_dense = build(enc.clone(), &docs, cfg(RankMode::Dense, None));
    let mut dm_prf = build(enc.clone(), &docs, cfg(RankMode::Lexical, Some(FROZEN_PRF)));
    let mut dm_fused = build(enc.clone(), &docs, cfg(fused, None));
    let mut dm_prf_fused = build(enc.clone(), &docs, cfg(fused, Some(FROZEN_PRF)));
    eprintln!("indexes: {:.1?}", t.elapsed());

    let names = [
        "bm25",
        "docmem_lexical",
        "docmem_dense_minilm",
        "hybrid_bm25_minilm_rrf",
        "docmem_prf",
        "docmem_fused_minilm",
        "docmem_prf_fused_minilm",
    ];
    let mut per: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut agg = vec![[0.0f64; 4]; names.len()];
    let t = Instant::now();
    println!("# per_query: qid\t{}", names.join("\t"));
    for qid in &qids {
        let q = &queries[*qid];
        let gains: &HashMap<u64, _> = &qrels[*qid];
        let relevant: HashSet<u64> = gains.keys().copied().collect();
        let rb = ids(bm25.search(q, DEPTH));
        let rd = ids(dm_dense.rank(q, DEPTH));
        let ranks = [
            rb.clone(),
            ids(dm_lex.rank(q, DEPTH)),
            rd.clone(),
            ids(reciprocal_rank_fusion(&[rb, rd], 60.0, DEPTH)),
            ids(dm_prf.rank(q, DEPTH)),
            ids(dm_fused.rank(q, DEPTH)),
            ids(dm_prf_fused.rank(q, DEPTH)),
        ];
        let mut row = qid.to_string();
        for (k, rank) in ranks.iter().enumerate() {
            let nd = metrics::ndcg_at_k(rank, gains, 10);
            per[k].push(nd);
            agg[k][0] += metrics::recall_at_k(rank, &relevant, 10);
            agg[k][1] += metrics::recall_at_k(rank, &relevant, 100);
            agg[k][2] += metrics::reciprocal_rank(&rank[..rank.len().min(10)], &relevant);
            agg[k][3] += metrics::average_precision(rank, &relevant);
            row.push_str(&format!("\t{nd:.6}"));
        }
        println!("{row}");
    }
    eprintln!("retrieve+score: {:.1?}", t.elapsed());
    let n = qids.len() as f64;
    println!(
        "\n# summary docs={} judged_queries={}",
        docs.len(),
        qids.len()
    );
    println!("arm\tnDCG@10\tR@10\tR@100\tMRR@10\tMAP");
    for (k, name) in names.iter().enumerate() {
        let a = agg[k];
        println!(
            "{name}\t{:.4}\t{:.4}\t{:.4}\t{:.4}\t{:.4}",
            per[k].iter().sum::<f64>() / n,
            a[0] / n,
            a[1] / n,
            a[2] / n,
            a[3] / n
        );
    }
    println!("\n# paired nDCG@10 delta vs bm25, 95% percentile bootstrap ({BOOT} resamples)");
    for k in 1..names.len() {
        let diff: Vec<f64> = per[k].iter().zip(&per[0]).map(|(a, b)| a - b).collect();
        let mean = diff.iter().sum::<f64>() / n;
        let wins = diff.iter().filter(|d| **d > 0.0).count();
        let losses = diff.iter().filter(|d| **d < 0.0).count();
        let cis: Vec<String> = SEEDS
            .iter()
            .map(|s| {
                let (lo, hi) = paired_ci(&diff, *s);
                format!("seed{s}=[{lo:+.4},{hi:+.4}]")
            })
            .collect();
        println!(
            "{}\tdelta={mean:+.4}\twins={wins}\tlosses={losses}\t{}",
            names[k],
            cis.join("\t")
        );
    }
    println!("\nsuperiority_claim: false (retrieval-only; see prereg decision rule)");
    Ok(())
}

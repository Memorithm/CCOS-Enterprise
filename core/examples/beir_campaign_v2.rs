//! # BEIR campaign v2 — `DocumentMemory` vs RAG baselines (prereg in docs/campaigns/).
//!
//! `--grid` scans `DocumentMemory` configurations and prints mean nDCG@10 per config. It is meant
//! for the **train** qrels only (a directory whose `qrels/test.tsv` is the train split). The default
//! mode runs the frozen arms below on the given split, prints per-query nDCG@10, summaries and paired
//! bootstrap intervals against BM25. Deterministic stdout; timings on stderr; no query is dropped.
//!
//! ```bash
//! cargo run --release -p ccos-core --example beir_campaign_v2 -- <beir-dir> [--grid]
//! ```

#[path = "support/beir_import.rs"]
mod beir_import;

use beir_import::{load_dataset, BeirDataset};
use ccos_core::doc_memory::{DocRankConfig, DocumentMemory, PrfConfig, RankMode};
use ccos_core::retrieval::{
    metrics, reciprocal_rank_fusion, Bm25Index, CcosEncoder, Encoder, LsaEncoder, Scored,
    SemanticRetriever,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

const DIM: usize = 512;
const RANK: usize = 128;
const DEPTH: usize = 100;
const BOOT: usize = 10_000;
const SEEDS: [u64; 3] = [1, 2, 3];

/// Frozen from the train-split grid (see prereg). Changing these after the prereg voids the run.
const FROZEN_PRF: PrfConfig = PrfConfig {
    fb_docs: FB_DOCS,
    fb_terms: FB_TERMS,
    orig_weight: ORIG_WEIGHT,
    max_df_ratio: MAX_DF,
};
const FB_DOCS: usize = 5;
const FB_TERMS: usize = 20;
const ORIG_WEIGHT: f32 = 0.3;
const MAX_DF: f32 = 0.05;
const FROZEN_ALPHA: f32 = 0.1;
const POOL: usize = 100;

fn main() {
    if let Err(e) = run() {
        eprintln!("beir_campaign_v2: {e}");
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .ok_or("usage: beir_campaign_v2 <dir> [--grid]")?;
    let grid = match args.get(1).map(String::as_str) {
        Some("--grid") => true,
        None => false,
        _ => return Err("usage: beir_campaign_v2 <dir> [--grid]".into()),
    };
    let BeirDataset {
        skipped_blank_docs: _,
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
    let lsa_enc = LsaEncoder::fit(&docs, DIM, RANK);
    let tfidf_enc = CcosEncoder::fit(&docs, DIM);
    eprintln!("encoder fit: {:.1?}", t.elapsed());

    if grid {
        println!("config\tnDCG@10");
        let mut configs: Vec<(String, DocRankConfig)> = Vec::new();
        for fb_docs in [3, 5, 10] {
            for fb_terms in [5, 10, 20] {
                for ow in [0.3f32, 0.5, 0.7] {
                    for df in [0.05f32, 0.1, 0.25] {
                        let p = PrfConfig {
                            fb_docs,
                            fb_terms,
                            orig_weight: ow,
                            max_df_ratio: df,
                        };
                        configs.push((
                            format!("prf d={fb_docs} t={fb_terms} ow={ow} df={df}"),
                            cfg(RankMode::Lexical, Some(p)),
                        ));
                    }
                }
            }
        }
        for alpha in [0.05f32, 0.1, 0.2, 0.3] {
            configs.push((
                format!("fused_lsa a={alpha}"),
                cfg(RankMode::Fused { alpha, pool: POOL }, None),
            ));
        }
        configs.push(("lexical".into(), cfg(RankMode::Lexical, None)));
        for (name, c) in configs {
            let mut m = build(lsa_enc.clone(), &docs, c);
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
    let mut tfidf = SemanticRetriever::new(tfidf_enc.clone());
    let mut lsa = SemanticRetriever::new(lsa_enc.clone());
    for (i, d) in docs.iter().enumerate() {
        tfidf.index_text(i as u64, d).unwrap();
        lsa.index_text(i as u64, d).unwrap();
    }
    let mut dm_lex = build(lsa_enc.clone(), &docs, cfg(RankMode::Lexical, None));
    let mut dm_dense = build(lsa_enc.clone(), &docs, cfg(RankMode::Dense, None));
    let mut dm_prf = build(
        lsa_enc.clone(),
        &docs,
        cfg(RankMode::Lexical, Some(FROZEN_PRF)),
    );
    let fused = RankMode::Fused {
        alpha: FROZEN_ALPHA,
        pool: POOL,
    };
    let mut dm_fused = build(lsa_enc.clone(), &docs, cfg(fused, None));
    let mut dm_prf_fused = build(lsa_enc.clone(), &docs, cfg(fused, Some(FROZEN_PRF)));
    eprintln!("indexes: {:.1?}", t.elapsed());

    let names = [
        "bm25",
        "tfidf_dense",
        "lsa_dense",
        "hybrid_bm25_lsa_rrf",
        "docmem_lexical",
        "docmem_dense_lsa",
        "docmem_prf",
        "docmem_fused_lsa",
        "docmem_prf_fused_lsa",
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
        let rl = ids(lsa.retrieve(q, DEPTH));
        let ranks = [
            rb.clone(),
            ids(tfidf.retrieve(q, DEPTH)),
            rl.clone(),
            ids(reciprocal_rank_fusion(&[rb, rl], 60.0, DEPTH)),
            ids(dm_lex.rank(q, DEPTH)),
            ids(dm_dense.rank(q, DEPTH)),
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

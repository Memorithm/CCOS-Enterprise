//! # Preregistered BEIR retrieval campaign (docs/campaigns/2026-10-27-beir-retrieval-prereg.md).
//!
//! Scores four deterministic RAG baselines (BM25, TF-IDF dense, LSA dense,
//! BM25⊕LSA RRF hybrid) and two CCOS governed-memory arms (`CcosMemory` with
//! `Recall::Semantic` and `Recall::Hybrid`) on the same strictly imported BEIR
//! corpus. Emits per-query nDCG@10 rows and paired bootstrap intervals for every
//! arm against the preregistered primary baseline (BM25). Deterministic: stdout
//! carries no timings. Losses and empty memory windows are kept, never filtered.
//!
//! ```bash
//! cargo run --release -p ccos-core --example beir_campaign -- <beir-dir> [--limit-docs N]
//! ```

#[path = "support/beir_import.rs"]
mod beir_import;

use beir_import::{load_dataset, BeirDataset};
use ccos_core::retrieval::{
    metrics, reciprocal_rank_fusion, Bm25Index, CcosEncoder, LsaEncoder, SemanticRetriever,
};
use ccos_core::{CcosMemory, ExternalMemory, Recall};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

const DIM: usize = 512;
const RANK: usize = 128;
const DEPTH: usize = 100;
const BOOT: usize = 10_000;
const SEEDS: [u64; 3] = [1, 2, 3];
const MEMORY_BUDGET_TOKENS: usize = usize::MAX / 4;

fn main() {
    if let Err(e) = run() {
        eprintln!("beir_campaign: {e}");
        std::process::exit(1);
    }
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Paired percentile bootstrap of mean(a - b) over queries; returns (lo, hi).
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

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .ok_or("usage: beir_campaign <dir> [--limit-docs N]")?;
    let limit: Option<usize> = match args.get(1).map(String::as_str) {
        Some("--limit-docs") => Some(
            args.get(2)
                .ok_or("missing N")?
                .parse()
                .map_err(|_| "bad N")?,
        ),
        None => None,
        _ => return Err("usage: beir_campaign <dir> [--limit-docs N]".into()),
    };
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
    let docs: Vec<String> = match limit {
        Some(n) => docs.into_iter().take(n).collect(),
        None => docs,
    };
    let mut qids: Vec<&String> = qrels.keys().collect();
    qids.sort();

    let t = Instant::now();
    let mut bm25 = Bm25Index::new(1.2, 0.75);
    for (i, d) in docs.iter().enumerate() {
        bm25.add(i as u64, d);
    }
    let mut tfidf = SemanticRetriever::new(CcosEncoder::fit(&docs, DIM));
    for (i, d) in docs.iter().enumerate() {
        tfidf.index_text(i as u64, d).unwrap();
    }
    let mut lsa = SemanticRetriever::new(LsaEncoder::fit(&docs, DIM, RANK));
    for (i, d) in docs.iter().enumerate() {
        lsa.index_text(i as u64, d).unwrap();
    }
    eprintln!("baseline indexes: {:.1?}", t.elapsed());

    let t = Instant::now();
    let mut mem = CcosMemory::new();
    for (i, d) in docs.iter().enumerate() {
        mem.ingest_source(&format!("doc/{i}.txt"), d);
    }
    eprintln!("ccos memory ingest: {:.1?}", t.elapsed());

    let names = [
        "bm25",
        "tfidf_dense",
        "lsa_dense",
        "hybrid_bm25_lsa_rrf",
        "ccos_memory_semantic",
        "ccos_memory_hybrid",
    ];
    let mut per: Vec<Vec<f64>> = vec![Vec::new(); names.len()];
    let mut agg = vec![[0.0f64; 4]; names.len()]; // r10, r100, mrr10, map
    let mut empty_windows = [0usize; 2];

    let mem_rank = |r: Recall| -> Vec<u64> {
        let w = mem.recall(&r, MEMORY_BUDGET_TOKENS);
        let mut seen = HashSet::new();
        w.items
            .iter()
            .filter_map(|it| {
                let s = it.uri.strip_prefix("file:doc/")?.strip_suffix(".txt")?;
                s.parse::<u64>().ok()
            })
            .filter(|id| seen.insert(*id))
            .take(DEPTH)
            .collect()
    };

    let t = Instant::now();
    println!("# per_query: qid\t{}", names.join("\t"));
    for qid in &qids {
        let q = &queries[*qid];
        let gains: &HashMap<u64, _> = &qrels[*qid];
        let relevant: HashSet<u64> = gains.keys().copied().collect();
        let rb: Vec<u64> = bm25.search(q, DEPTH).into_iter().map(|s| s.id).collect();
        let rt: Vec<u64> = tfidf.retrieve(q, DEPTH).into_iter().map(|s| s.id).collect();
        let rl: Vec<u64> = lsa.retrieve(q, DEPTH).into_iter().map(|s| s.id).collect();
        let rh: Vec<u64> = reciprocal_rank_fusion(&[rb.clone(), rl.clone()], 60.0, DEPTH)
            .into_iter()
            .map(|s| s.id)
            .collect();
        let ms = mem_rank(Recall::Semantic(q.clone()));
        let mh = mem_rank(Recall::Hybrid(q.clone()));
        empty_windows[0] += ms.is_empty() as usize;
        empty_windows[1] += mh.is_empty() as usize;
        let mut row = qid.to_string();
        for (k, rank) in [&rb, &rt, &rl, &rh, &ms, &mh].iter().enumerate() {
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
        "\n# summary dataset={dir} docs={} judged_queries={}",
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
    println!(
        "empty_windows\tccos_memory_semantic={}\tccos_memory_hybrid={}",
        empty_windows[0], empty_windows[1]
    );
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

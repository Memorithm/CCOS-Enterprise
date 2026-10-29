//! # BEIR-style evaluation — deterministic retrievers on an external IR corpus.
//!
//! Reads `corpus.jsonl`, `queries.jsonl` and `qrels/test.tsv` in full before
//! constructing any index. Invalid records fail with a file/line diagnostic.
//! `--validate-only` checks the population without indexing or scoring.
//!
//! ```bash
//! cargo run --release --example beir_eval -- data/beir/scifact
//! cargo run --example beir_eval -- data/beir/scifact --validate-only
//! cargo test --example beir_eval
//! ```
//!
//! Datasets are not committed. See `docs/BEIR_IMPORT_CONTRACT.md` for the input
//! contract and provenance. This evaluates retrieval, not LLM answer quality.

#[path = "support/beir_import.rs"]
mod beir_import;

use beir_import::{load_dataset, BeirDataset};
use ccos_core::retrieval::{
    metrics, reciprocal_rank_fusion, Bm25Index, CcosEncoder, LsaEncoder, SemanticRetriever,
};
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

const DIM: usize = 512; // TF-IDF hash width
const RANK: usize = 128; // LSA latent rank
const DEPTH: usize = 100; // retrieval depth (Recall@100 / MAP cut)

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid BEIR input: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut directory = None;
    let mut validate_only = false;
    for argument in std::env::args().skip(1) {
        if argument == "--validate-only" && !validate_only {
            validate_only = true;
        } else if argument.starts_with('-') || directory.replace(argument).is_some() {
            return Err("usage: beir_eval [dataset-directory] [--validate-only]".into());
        }
    }
    let directory = directory.unwrap_or_else(|| "data/beir/scifact".to_string());
    let dir = Path::new(&directory);
    let t0 = Instant::now();
    let BeirDataset {
        docs,
        queries,
        qrels,
        qrel_stats,
    } = load_dataset(dir)?;
    let mut qids: Vec<&String> = qrels.keys().collect();
    qids.sort(); // deterministic evaluation order
    eprintln!(
        "strict import: corpus_rows={} query_rows={} qrel_rows={} positive={} non_positive={} positively_judged_queries={} rejected=0",
        docs.len(), queries.len(), qrel_stats.data_rows, qrel_stats.positive_rows,
        qrel_stats.non_positive_rows, qrel_stats.positive_queries,
    );
    eprintln!("load: {:.1?}", t0.elapsed());
    if validate_only {
        println!("BEIR input valid; indexing and scoring not performed");
        return Ok(());
    }

    println!(
        "# BEIR-style evaluation — deterministic retrieval on {}",
        dir.display()
    );
    println!(
        "\ncorpus: {} docs   queries: {} judged (of {} shipped)   qrels: graded, test split, strict import\n",
        docs.len(),
        qids.len(),
        queries.len(),
    );

    // Index the three retrievers over the SAME fully validated corpus.
    let t = Instant::now();
    let mut bm25 = Bm25Index::new(1.2, 0.75);
    for (i, d) in docs.iter().enumerate() {
        bm25.add(i as u64, d);
    }
    eprintln!("bm25 index: {:.1?}", t.elapsed());

    let t = Instant::now();
    let mut tfidf = SemanticRetriever::new(CcosEncoder::fit(&docs, DIM));
    for (i, d) in docs.iter().enumerate() {
        tfidf.index_text(i as u64, d).unwrap();
    }
    eprintln!("tf-idf dense index: {:.1?}", t.elapsed());

    let t = Instant::now();
    let mut lsa = SemanticRetriever::new(LsaEncoder::fit(&docs, DIM, RANK));
    for (i, d) in docs.iter().enumerate() {
        lsa.index_text(i as u64, d).unwrap();
    }
    eprintln!("lsa fit+index: {:.1?}", t.elapsed());

    // Hybrid = RRF over the BM25 and LSA rankings (no second fit needed).
    #[derive(Default)]
    struct Agg {
        ndcg10: f64,
        r10: f64,
        r100: f64,
        mrr10: f64,
        map: f64,
    }
    let mut aggs: [Agg; 4] = Default::default();
    let names = [
        "BM25 (k1=1.2 b=0.75)",
        "TF-IDF dense",
        "LSA dense",
        "hybrid BM25⊕LSA (RRF)",
    ];

    let t = Instant::now();
    for qid in &qids {
        let qtext = &queries[*qid];
        let gains = &qrels[*qid];
        let relevant: HashSet<u64> = gains.keys().copied().collect();

        let rank_bm25: Vec<u64> = bm25
            .search(qtext, DEPTH)
            .into_iter()
            .map(|s| s.id)
            .collect();
        let rank_tfidf: Vec<u64> = tfidf
            .retrieve(qtext, DEPTH)
            .into_iter()
            .map(|s| s.id)
            .collect();
        let rank_lsa: Vec<u64> = lsa
            .retrieve(qtext, DEPTH)
            .into_iter()
            .map(|s| s.id)
            .collect();
        let rank_hyb: Vec<u64> =
            reciprocal_rank_fusion(&[rank_bm25.clone(), rank_lsa.clone()], 60.0, DEPTH)
                .into_iter()
                .map(|s| s.id)
                .collect();

        for (agg, rank) in aggs
            .iter_mut()
            .zip([&rank_bm25, &rank_tfidf, &rank_lsa, &rank_hyb])
        {
            agg.ndcg10 += metrics::ndcg_at_k(rank, gains, 10);
            agg.r10 += metrics::recall_at_k(rank, &relevant, 10);
            agg.r100 += metrics::recall_at_k(rank, &relevant, 100);
            let top10 = &rank[..rank.len().min(10)];
            agg.mrr10 += metrics::reciprocal_rank(top10, &relevant);
            agg.map += metrics::average_precision(rank, &relevant);
        }
    }
    eprintln!(
        "retrieve+score ({} queries × 4 systems): {:.1?}",
        qids.len(),
        t.elapsed()
    );

    let n = qids.len() as f64;
    println!(
        "  {:<24}{:>8}{:>8}{:>8}{:>8}{:>8}",
        "system", "nDCG@10", "R@10", "R@100", "MRR@10", "MAP"
    );
    println!("  {}", "-".repeat(64));
    for (name, a) in names.iter().zip(&aggs) {
        println!(
            "  {:<24}{:>8.3}{:>8.3}{:>8.3}{:>8.3}{:>8.3}",
            name,
            a.ndcg10 / n,
            a.r10 / n,
            a.r100 / n,
            a.mrr10 / n,
            a.map / n,
        );
    }
    println!(
        "\nSame validated corpus and positively judged queries; BM25, TF-IDF, LSA and RRF.\n\
         Retrieval metrics only: no new LLM-quality or modern-RAG superiority claim.\n\
         Historical measurements in docs/MEASUREMENT_beir.md are not reproduced by validation-only mode."
    );
    Ok(())
}

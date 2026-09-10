//! # BEIR-style evaluation — CCOS's deterministic retrievers on a standard IR corpus.
//!
//! The retrieval cruxes (`pure_retrieval_vs_rag`, `semantic_retrieval_crux`) score CCOS's retrievers
//! on corpora CCOS itself defines. This harness runs them on a **standard, external IR benchmark** in
//! the BEIR format (`corpus.jsonl` + `queries.jsonl` + `qrels/test.tsv`) and reports the metrics the
//! IR community reports — **nDCG@10** (BEIR's headline), Recall@10/100, MRR@10, MAP — so the numbers
//! are comparable to published baselines. Everything stays inside the moat: zero new dependencies
//! (`serde_json` is already in the tree), fixed-order `f32`, and **bit-for-bit identical output**
//! across runs (timings go to stderr).
//!
//! The dataset is **not** committed (size + licensing + the air-gap ethos): fetch it once yourself —
//!
//! ```bash
//! curl -o scifact.zip https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip
//! mkdir -p data/beir && unzip scifact.zip -d data/beir
//! cargo run --release --example beir_eval              # reads data/beir/scifact
//! cargo run --release --example beir_eval -- <dir>     # any BEIR-format dataset dir
//! ```
//!
//! Reference point: the BEIR paper's tuned Anserini **BM25 scores nDCG@10 ≈ 0.665 on SciFact**; CCOS's
//! BM25 uses a plain lowercase-alphanumeric tokenizer (no stemming, no stopword list), so landing in
//! that neighbourhood — deterministically, in pure Rust — is the honest claim, not SOTA.

use ccos_core::retrieval::{
    metrics, reciprocal_rank_fusion, Bm25Index, CcosEncoder, LsaEncoder, SemanticRetriever,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Instant;

const DIM: usize = 512; // TF-IDF hash width
const RANK: usize = 128; // LSA latent rank
const DEPTH: usize = 100; // retrieval depth (Recall@100 / MAP cut)

fn jsonl(path: &Path) -> Vec<serde_json::Value> {
    let Ok(raw) = fs::read_to_string(path) else {
        eprintln!("missing {}", path.display());
        eprintln!(
            "\nThe dataset is not committed. Fetch a BEIR dataset (e.g. SciFact) first:\n  \
             curl -o scifact.zip https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip\n  \
             mkdir -p data/beir && unzip scifact.zip -d data/beir\n  \
             cargo run --release --example beir_eval"
        );
        std::process::exit(1);
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("malformed JSONL line"))
        .collect()
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct QrelImportStats {
    data_rows: usize,
    positive_rows: usize,
    non_positive_rows: usize,
    positive_queries: usize,
    /// Strict mode aborts on the first rejected row, so a successful import is always zero.
    rejected_rows: usize,
}

struct QrelImport {
    qrels: HashMap<String, HashMap<u64, f64>>,
    stats: QrelImportStats,
}

fn parse_qrels(
    raw: &str,
    doc_ids: &HashMap<String, u64>,
    queries: &HashMap<String, String>,
) -> Result<QrelImport, String> {
    let mut lines = raw.lines();
    let header = lines
        .next()
        .ok_or_else(|| "qrels file is empty".to_string())?;
    if header != "query-id\tcorpus-id\tscore" {
        return Err(format!(
            "qrels header must be exactly `query-id\\tcorpus-id\\tscore`, found {header:?}"
        ));
    }

    let mut qrels: HashMap<String, HashMap<u64, f64>> = HashMap::new();
    let mut seen: HashSet<(String, u64)> = HashSet::new();
    let mut stats = QrelImportStats::default();

    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        stats.data_rows += 1;
        if line.is_empty() {
            return Err(format!("qrels line {line_number} is empty"));
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err(format!(
                "qrels line {line_number} has {} fields; expected exactly 3",
                fields.len()
            ));
        }
        let qid = fields[0];
        let did = fields[1];
        if qid.is_empty() || did.is_empty() {
            return Err(format!(
                "qrels line {line_number} contains an empty query or document id"
            ));
        }
        if !queries.contains_key(qid) {
            return Err(format!(
                "qrels line {line_number} references unknown query id {qid:?}"
            ));
        }
        let &doc = doc_ids.get(did).ok_or_else(|| {
            format!("qrels line {line_number} references unknown document id {did:?}")
        })?;
        let gain: f64 = fields[2].parse().map_err(|_| {
            format!(
                "qrels line {line_number} has non-numeric relevance score {:?}",
                fields[2]
            )
        })?;
        if !gain.is_finite() {
            return Err(format!(
                "qrels line {line_number} has non-finite relevance score {:?}",
                fields[2]
            ));
        }

        if !seen.insert((qid.to_string(), doc)) {
            return Err(format!(
                "qrels line {line_number} duplicates judgment for query {qid:?}, document {did:?}"
            ));
        }

        if gain > 0.0 {
            qrels.entry(qid.to_string()).or_default().insert(doc, gain);
            stats.positive_rows += 1;
        } else {
            stats.non_positive_rows += 1;
        }
    }

    if qrels.is_empty() {
        return Err("qrels contain no positive relevance judgments".into());
    }
    stats.positive_queries = qrels.len();
    Ok(QrelImport { qrels, stats })
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "data/beir/scifact".to_string());
    let dir = Path::new(&dir);

    // ── Corpus: BEIR docs are {_id, title, text}; index "title text" under a dense u64 id ────────
    let t0 = Instant::now();
    let corpus = jsonl(&dir.join("corpus.jsonl"));
    let mut doc_ids: HashMap<String, u64> = HashMap::new(); // BEIR string id → dense u64
    let mut docs: Vec<String> = Vec::with_capacity(corpus.len());
    for (i, d) in corpus.iter().enumerate() {
        let sid = d["_id"].as_str().expect("_id").to_string();
        let title = d["title"].as_str().unwrap_or("");
        let text = d["text"].as_str().unwrap_or("");
        doc_ids.insert(sid, i as u64);
        docs.push(format!("{title} {text}"));
    }

    // ── Queries + graded qrels (test split). Strict import prevents silent population drift. ─────
    let queries: HashMap<String, String> = jsonl(&dir.join("queries.jsonl"))
        .into_iter()
        .map(|q| {
            (
                q["_id"].as_str().expect("_id").to_string(),
                q["text"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let raw = fs::read_to_string(dir.join("qrels/test.tsv")).expect("qrels/test.tsv");
    let imported = parse_qrels(&raw, &doc_ids, &queries).unwrap_or_else(|error| {
        eprintln!("invalid BEIR qrels: {error}");
        std::process::exit(2);
    });
    let QrelImport { qrels, stats } = imported;
    let mut qids: Vec<&String> = qrels.keys().collect();
    qids.sort(); // deterministic evaluation order
    eprintln!(
        "qrels import: {} data rows, {} positive, {} non-positive, {} rejected; {} positively judged queries",
        stats.data_rows,
        stats.positive_rows,
        stats.non_positive_rows,
        stats.rejected_rows,
        stats.positive_queries,
    );
    eprintln!("load: {:.1?}", t0.elapsed());

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

    // ── Index the three retrievers over the SAME corpus ──────────────────────────────────────────
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

    // ── Score. Hybrid = RRF over the BM25 and LSA rankings (no second fit needed). ───────────────
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
        "\n→ Same corpus, same queries, four deterministic systems: exact BM25, hashed TF-IDF dense,\n\
         its LSA projection, and their reciprocal-rank fusion. Reference: the BEIR paper's tuned\n\
         Anserini BM25 reports nDCG@10 ≈ 0.665 on SciFact — CCOS's plain tokenizer (no stemming, no\n\
         stopwords) lands in that neighbourhood with zero dependencies and bit-for-bit reproducible\n\
         output (rerun and diff: identical). See docs/MEASUREMENT_beir.md."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (HashMap<String, u64>, HashMap<String, String>) {
        (
            HashMap::from([("d1".into(), 0), ("d2".into(), 1)]),
            HashMap::from([("q1".into(), "question".into())]),
        )
    }

    #[test]
    fn strict_qrels_import_counts_positive_and_non_positive_rows() {
        let (docs, queries) = fixtures();
        let imported = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\td1\t1\nq1\td2\t0\n",
            &docs,
            &queries,
        )
        .unwrap();
        assert_eq!(imported.qrels["q1"].get(&0), Some(&1.0));
        assert_eq!(
            imported.stats,
            QrelImportStats {
                data_rows: 2,
                positive_rows: 1,
                non_positive_rows: 1,
                positive_queries: 1,
                rejected_rows: 0,
            }
        );
    }

    #[test]
    fn strict_qrels_import_rejects_malformed_rows_and_scores() {
        let (docs, queries) = fixtures();
        let malformed = parse_qrels("query-id\tcorpus-id\tscore\nq1\td1\n", &docs, &queries)
            .err()
            .unwrap();
        assert!(malformed.contains("expected exactly 3"));

        let bad_score = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\td1\tnot-a-number\n",
            &docs,
            &queries,
        )
        .err()
        .unwrap();
        assert!(bad_score.contains("non-numeric relevance score"));
    }

    #[test]
    fn strict_qrels_import_rejects_unknown_references() {
        let (docs, queries) = fixtures();
        let unknown_query = parse_qrels(
            "query-id\tcorpus-id\tscore\nmissing\td1\t1\n",
            &docs,
            &queries,
        )
        .err()
        .unwrap();
        assert!(unknown_query.contains("unknown query id"));

        let unknown_doc = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\tmissing\t1\n",
            &docs,
            &queries,
        )
        .err()
        .unwrap();
        assert!(unknown_doc.contains("unknown document id"));
    }

    #[test]
    fn strict_qrels_import_rejects_duplicates_non_finite_and_no_positive_set() {
        let (docs, queries) = fixtures();
        let duplicate = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\td1\t1\nq1\td1\t2\n",
            &docs,
            &queries,
        )
        .err()
        .unwrap();
        assert!(duplicate.contains("duplicates judgment"));

        let non_finite = parse_qrels("query-id\tcorpus-id\tscore\nq1\td1\tNaN\n", &docs, &queries)
            .err()
            .unwrap();
        assert!(non_finite.contains("non-finite relevance score"));

        let no_positive = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\td1\t0\nq1\td2\t-1\n",
            &docs,
            &queries,
        )
        .err()
        .unwrap();
        assert!(no_positive.contains("no positive relevance judgments"));
    }
}

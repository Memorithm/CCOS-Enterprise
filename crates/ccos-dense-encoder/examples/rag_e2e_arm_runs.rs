//! # RAG E2E retrieval arms -> TREC runs (no metrics, no generation)
//!
//! Prereg: `docs/campaigns/2026-11-02-rag-e2e-prereg.md`. Reads the campaign-schema
//! `corpus.jsonl` / `queries.jsonl` written by `scripts/rag-e2e-squad-export.py` and writes one
//! TREC run per retrieval arm (`<out>/<arm>.trec`, depth 100, original doc/query ids) for
//! `scripts/rag-e2e-rank-adapter.py --format trec`. ALL queries are ranked (answerable and
//! unanswerable); nothing is scored here. Arms: `lexical` (BM25 k1=1.2 b=0.75), `dense`
//! (MiniLM exact), `hybrid` (RRF k=60 of the two), `ccos` (`DocumentMemory` fused, alpha=0.5
//! frozen in v3). The `reranked` arm needs the pinned cross-encoder, which has no runner in
//! this repo yet: it is NOT emitted.
//!
//! ```bash
//! cargo run --release -p ccos-dense-encoder --example rag_e2e_arm_runs -- <export-dir> <minilm-dir> <out-dir>
//! ```

use ccos_core::doc_memory::{DocRankConfig, DocumentMemory, RankMode};
use ccos_core::retrieval::{reciprocal_rank_fusion, Bm25Index, Encoder, Scored};
use ccos_dense_encoder::{BertSentenceEncoder, CachedEncoder, DEFAULT_MAX_LEN, DEFAULT_THREADS};
use std::fmt::Write as _;
use std::path::Path;

const DEPTH: usize = 100;
const POOL: usize = 100;
const FROZEN_ALPHA: f32 = 0.5;

fn read_rows(path: &Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?;
        let id = v["id"]
            .as_str()
            .ok_or(format!("{}:{}: missing id", path.display(), n + 1))?;
        let t = v["text"]
            .as_str()
            .ok_or(format!("{}:{}: missing text", path.display(), n + 1))?;
        if t.trim().is_empty() {
            return Err(format!("{}:{}: blank text", path.display(), n + 1));
        }
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            return Err(format!("{}:{}: id not TREC-safe", path.display(), n + 1));
        }
        out.push((id.to_string(), t.to_string()));
    }
    Ok(out)
}

fn trec(arm: &str, qid: &str, ranked: &[Scored], doc_ids: &[String], buf: &mut String) {
    for (r, s) in ranked.iter().enumerate() {
        assert!(s.score.is_finite(), "non-finite score");
        let _ = writeln!(
            buf,
            "{qid} Q0 {} {} {:.9} {arm}",
            doc_ids[s.id as usize],
            r + 1,
            s.score
        );
    }
}

fn run() -> Result<(), String> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [dir, model, out] = a.as_slice() else {
        return Err("usage: rag_e2e_arm_runs <export-dir> <minilm-dir> <out-dir>".into());
    };
    let docs = read_rows(&Path::new(dir).join("corpus.jsonl"))?;
    let queries = read_rows(&Path::new(dir).join("queries.jsonl"))?;
    let doc_ids: Vec<String> = docs.iter().map(|d| d.0.clone()).collect();
    let texts: Vec<String> = docs.iter().map(|d| d.1.clone()).collect();
    let bert = BertSentenceEncoder::load(Path::new(model), DEFAULT_MAX_LEN, DEFAULT_THREADS)
        .map_err(|e| e.to_string())?;
    let mut enc = CachedEncoder::new(bert);
    enc.encode_batch(&texts);
    enc.encode_batch(&queries.iter().map(|q| q.1.clone()).collect::<Vec<_>>());
    let mut bm25 = Bm25Index::new(1.2, 0.75);
    let build = |mode| {
        let mut m = DocumentMemory::new(
            enc.clone(),
            DocRankConfig {
                mode,
                ..Default::default()
            },
        );
        for (i, d) in texts.iter().enumerate() {
            m.upsert(i as u64, d);
        }
        m
    };
    let mut dense = build(RankMode::Dense);
    let mut ccos = build(RankMode::Fused {
        alpha: FROZEN_ALPHA,
        pool: POOL,
    });
    for (i, d) in texts.iter().enumerate() {
        bm25.add(i as u64, d);
    }
    let mut bufs = [String::new(), String::new(), String::new(), String::new()];
    let names = ["lexical", "dense", "hybrid", "ccos"];
    for (qid, q) in &queries {
        let rb = bm25.search(q, DEPTH);
        let rd = dense.rank(q, DEPTH);
        let ids = |v: &[Scored]| v.iter().map(|s| s.id).collect::<Vec<u64>>();
        let rh = reciprocal_rank_fusion(&[ids(&rb), ids(&rd)], 60.0, DEPTH);
        let rc = ccos.rank(q, DEPTH);
        for (k, r) in [&rb, &rd, &rh, &rc].into_iter().enumerate() {
            trec(names[k], qid, r, &doc_ids, &mut bufs[k]);
        }
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    for (k, n) in names.iter().enumerate() {
        std::fs::write(Path::new(out).join(format!("{n}.trec")), &bufs[k])
            .map_err(|e| e.to_string())?;
    }
    eprintln!(
        "docs={} queries={} arms={:?} (reranked: not emitted)",
        docs.len(),
        queries.len(),
        names
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("rag_e2e_arm_runs: {e}");
        std::process::exit(1);
    }
}

//! Prereg v5 amendment (`docs/campaigns/2026-10-29-beir-v5-fiqa-amendment-prereg.md`):
//! opt-in **skip-unretrievable** handling of corpus records whose title and text are both blank.
//!
//! The vendored strict importer (`core/examples/support/beir_import.rs`, hash-pinned to
//! CCOS-Core) is not modified. Instead the blank records are removed into a staged copy of the
//! dataset, the staged copy goes through the unchanged strict importer, and every positive
//! judgment that pointed at a removed record is re-attached under a sentinel document ID
//! (counting down from `u64::MAX`). Such a judgment counts toward the query's ideal DCG but no
//! arm can retrieve it; no judged query or judgment is dropped.

use crate::beir_import::{load_dataset, BeirDataset};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Staged {
    pub dataset: BeirDataset,
    pub skipped_blank_docs: usize,
    pub reattached_judgments: usize,
}

fn is_blank(line: &str) -> Result<Option<String>, String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .is_empty()
    };
    if field("title") && field("text") {
        if let Some(id) = v.get("_id").and_then(|x| x.as_str()) {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

pub fn load_skipping_blank(root: &Path) -> Result<Staged, String> {
    let read = |p: PathBuf| fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
    let corpus = read(root.join("corpus.jsonl"))?;
    let mut sentinel: HashMap<String, u64> = HashMap::new();
    let mut kept = String::with_capacity(corpus.len());
    for line in corpus.lines() {
        // Malformed rows are left for the strict importer to reject with its own diagnostic.
        match is_blank(line) {
            Ok(Some(id)) if !sentinel.contains_key(&id) => {
                let s = u64::MAX - sentinel.len() as u64;
                sentinel.insert(id, s);
            }
            _ => {
                kept.push_str(line);
                kept.push('\n');
            }
        }
    }
    let qrels = read(root.join("qrels/test.tsv"))?;
    let mut kept_qrels = String::with_capacity(qrels.len());
    let mut removed: Vec<(String, u64, f64)> = Vec::new();
    for (i, line) in qrels.lines().enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        if i > 0 && f.len() == 3 {
            if let Some(&s) = sentinel.get(f[1]) {
                let gain: f64 = f[2]
                    .parse()
                    .map_err(|_| format!("qrels/test.tsv:{}: non-numeric score", i + 1))?;
                removed.push((f[0].to_string(), s, gain));
                continue;
            }
        }
        kept_qrels.push_str(line);
        kept_qrels.push('\n');
    }
    let stage = std::env::temp_dir().join(format!("beir-v5-stage-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("qrels")).map_err(|e| e.to_string())?;
    let write = |p: PathBuf, s: &str| fs::write(&p, s).map_err(|e| format!("{}: {e}", p.display()));
    write(stage.join("corpus.jsonl"), &kept)?;
    write(
        stage.join("queries.jsonl"),
        &read(root.join("queries.jsonl"))?,
    )?;
    write(stage.join("qrels/test.tsv"), &kept_qrels)?;
    let loaded = load_dataset(&stage);
    let _ = fs::remove_dir_all(&stage);
    let mut dataset = loaded?;
    let mut reattached = 0;
    for (qid, s, gain) in removed {
        if !dataset.queries.contains_key(&qid) {
            return Err(format!(
                "judgment on blank doc references unknown query {qid:?}"
            ));
        }
        if gain > 0.0 {
            dataset.qrels.entry(qid).or_default().insert(s, gain);
            reattached += 1;
        }
    }
    Ok(Staged {
        dataset,
        skipped_blank_docs: sentinel.len(),
        reattached_judgments: reattached,
    })
}

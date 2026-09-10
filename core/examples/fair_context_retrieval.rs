//! Fair, deterministic context-retrieval benchmark.
//!
//! This benchmark deliberately does **not** claim end-to-end answer quality. It
//! measures the necessary retrieval/selection condition only: under one shared
//! estimated-token budget, did a strategy surface all evidence documents needed
//! by a synthetic causal task?
//!
//! Design constraints:
//! - opaque document ids: no `chain`/answer-bearing filename convention;
//! - identical natural-language query for every query-driven strategy;
//! - real in-tree BM25, TF-IDF dense retrieval and BM25+TF-IDF RRF baselines;
//! - graph-walk and CCOS query-driven strategies start from the same BM25 hit;
//! - workspace-anchor CCOS is reported separately and explicitly marked assisted;
//! - budget enforcement is strict: no first-document overshoot exception;
//! - the token budget is labelled as an estimate (`ceil(chars / 4)`), not a model
//!   tokenizer count.

use ccos_core::memory::{EdgeType, MemoryGraph, NodeType};
use ccos_core::region_engine::ContextRegionEngine;
use ccos_core::retrieval::{Bm25Index, CcosEncoder, HybridRetriever, SemanticRetriever};
use ccos_core::util::sha256_hex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const SCHEMA_VERSION: u32 = 1;
const TASKS_PER_DIAMETER: usize = 24;
const DECOYS: usize = 12;
const BUDGET_TOKENS: usize = 600;
const EMBEDDING_DIM: usize = 256;

const STRATEGIES: [(&str, bool); 7] = [
    ("bm25", false),
    ("tfidf-dense", false),
    ("bm25-tfidf-rrf", false),
    ("graph-1hop", false),
    ("graph-bfs", false),
    ("ccos-query-region", false),
    ("ccos-workspace-anchor", true),
];

#[derive(Debug, Clone)]
struct Doc {
    id: String,
    text: String,
}

#[derive(Debug, Clone)]
struct Task {
    docs: Vec<Doc>,
    required: BTreeSet<String>,
    edges: Vec<(String, String)>,
    anchor: String,
    query: String,
}

#[derive(Debug, Default, Clone, Copy)]
struct Acc {
    tasks: usize,
    fully_covered: usize,
    coverage_sum: f64,
    tokens_sum: usize,
}

#[derive(Debug, Serialize)]
struct BenchmarkRow {
    diameter: u32,
    strategy: &'static str,
    assisted_anchor: bool,
    tasks: usize,
    full_evidence_rate: f64,
    mean_required_coverage: f64,
    mean_estimated_tokens: f64,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    schema_version: u32,
    claim_scope: &'static str,
    token_budget_kind: &'static str,
    budget_tokens: usize,
    tasks_per_diameter: usize,
    decoys_per_task: usize,
    rows: Vec<BenchmarkRow>,
}

fn opaque_id(task: usize, kind: &str, ordinal: usize) -> String {
    let digest = sha256_hex(&format!("fair-context:v1:{task}:{kind}:{ordinal}"));
    format!("doc:{}", &digest[..20])
}

fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

fn filler(task: usize, ordinal: usize) -> String {
    format!(
        "\n// Synthetic benchmark notes {task}-{ordinal}.\n// This padding has no query-specific identifiers.\n{}",
        "// neutral context padding for budget pressure\n".repeat(8)
    )
}

fn build_task(task_no: usize, diameter: u32) -> Task {
    let chain_len = diameter as usize + 1;
    let mut docs = Vec::with_capacity(chain_len + DECOYS + 1);
    let mut required = BTreeSet::new();
    let mut edges = Vec::with_capacity(chain_len.saturating_sub(1));
    let mut chain_ids: Vec<String> = Vec::with_capacity(chain_len);

    let base = 3 + (task_no % 17) as i64;
    let base_symbol = format!("base_value_{task_no}");

    for i in 0..chain_len {
        let id = opaque_id(task_no, "evidence", i);
        let symbol = if i + 1 == chain_len {
            format!("requested_result_{task_no}")
        } else {
            format!("stage_{task_no}_{i}")
        };
        let text = if i == 0 {
            format!(
                "pub const {base_symbol}: i64 = {base};\n{}",
                filler(task_no, i)
            )
        } else {
            let delta = 1 + ((task_no + i) % 7) as i64;
            let previous = if i == 1 {
                base_symbol.clone()
            } else {
                format!("stage_{task_no}_{}()", i - 1)
            };
            format!(
                "pub fn {symbol}() -> i64 {{ {previous} + {delta} }}\n{}",
                filler(task_no, i)
            )
        };

        if let Some(prev) = chain_ids.last() {
            edges.push((prev.clone(), id.clone()));
        }
        required.insert(id.clone());
        chain_ids.push(id.clone());
        docs.push(Doc { id, text });
    }

    // Add unrelated files. One noisy decoy mentions the requested symbol several
    // times in prose. The query itself is not modified to favour the decoy.
    let requested = format!("requested_result_{task_no}");
    for k in 0..DECOYS {
        let id = opaque_id(task_no, "decoy", k);
        let text = if k == task_no % DECOYS {
            format!(
                "// migration note: {requested} {requested} {requested}\n\
                 // historical compatibility text; no live implementation here\n\
                 pub fn utility_{task_no}_{k}(x: i64) -> i64 {{ x + {k} }}\n{}",
                filler(task_no, chain_len + k)
            )
        } else {
            format!(
                "pub fn utility_{task_no}_{k}(x: i64) -> i64 {{ x + {k} }}\n{}",
                filler(task_no, chain_len + k)
            )
        };
        docs.push(Doc { id, text });
    }

    let anchor = chain_ids
        .last()
        .cloned()
        .expect("every generated task has at least one evidence document");
    Task {
        docs,
        required,
        edges,
        anchor,
        query: format!(
            "What integer does {requested} return? Use the live implementation and its dependencies."
        ),
    }
}

fn build_graph(task: &Task) -> MemoryGraph {
    let mut graph = MemoryGraph::new(0.0, usize::MAX);
    for doc in &task.docs {
        graph.upsert_node(
            doc.id.clone().into(),
            doc.id.clone(),
            doc.text.clone(),
            NodeType::Module,
        );
    }
    for (source, target) in &task.edges {
        graph.add_edge(
            source.clone().into(),
            target.clone().into(),
            0.9,
            EdgeType::DependsOn,
        );
    }
    graph
}

fn id_map(task: &Task) -> BTreeMap<u64, String> {
    task.docs
        .iter()
        .enumerate()
        .map(|(index, doc)| (index as u64, doc.id.clone()))
        .collect()
}

fn bm25_order(task: &Task) -> Vec<String> {
    let by_num = id_map(task);
    let mut index = Bm25Index::default();
    for (n, doc) in task.docs.iter().enumerate() {
        index.add(n as u64, &doc.text);
    }
    index
        .search(&task.query, task.docs.len())
        .into_iter()
        .filter_map(|hit| by_num.get(&hit.id).cloned())
        .collect()
}

fn dense_order(task: &Task) -> Vec<String> {
    let by_num = id_map(task);
    let corpus: Vec<String> = task.docs.iter().map(|d| d.text.clone()).collect();
    let encoder = CcosEncoder::fit(&corpus, EMBEDDING_DIM);
    let mut retriever = SemanticRetriever::new(encoder);
    for (n, doc) in task.docs.iter().enumerate() {
        retriever
            .index_text(n as u64, &doc.text)
            .expect("CCOS encoder and dense index dimensions must agree");
    }
    retriever
        .retrieve(&task.query, task.docs.len())
        .into_iter()
        .filter_map(|hit| by_num.get(&hit.id).cloned())
        .collect()
}

fn hybrid_order(task: &Task) -> Vec<String> {
    let by_num = id_map(task);
    let corpus: Vec<String> = task.docs.iter().map(|d| d.text.clone()).collect();
    let encoder = CcosEncoder::fit(&corpus, EMBEDDING_DIM);
    let mut retriever = HybridRetriever::new(encoder, 60.0);
    for (n, doc) in task.docs.iter().enumerate() {
        retriever
            .index_text(n as u64, &doc.text)
            .expect("CCOS encoder and hybrid dense index dimensions must agree");
    }
    retriever
        .retrieve(&task.query, task.docs.len())
        .into_iter()
        .filter_map(|hit| by_num.get(&hit.id).cloned())
        .collect()
}

fn neighbors(graph: &MemoryGraph, id: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for edge in graph.edges() {
        if edge.source.0 == id {
            out.insert(edge.target.0.clone());
        } else if edge.target.0 == id {
            out.insert(edge.source.0.clone());
        }
    }
    out.into_iter().collect()
}

fn bfs_order(graph: &MemoryGraph, seed: &str) -> Vec<String> {
    let mut queue = VecDeque::from([seed.to_owned()]);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        out.push(id.clone());
        for next in neighbors(graph, &id) {
            if !seen.contains(&next) {
                queue.push_back(next);
            }
        }
    }
    out
}

fn one_hop_order(graph: &MemoryGraph, seed: &str) -> Vec<String> {
    let mut out = vec![seed.to_owned()];
    out.extend(neighbors(graph, seed));
    out
}

fn region_order(graph: &MemoryGraph, seed: &str) -> Vec<String> {
    let clusters = ContextRegionEngine::cluster_nodes(graph);
    let Some(members) = clusters
        .values()
        .find(|members| members.iter().any(|id| id == seed))
    else {
        return vec![seed.to_owned()];
    };
    let allowed: BTreeSet<String> = members.iter().cloned().collect();
    bfs_order(graph, seed)
        .into_iter()
        .filter(|id| allowed.contains(id))
        .collect()
}

fn strict_budget(task: &Task, ordered: Vec<String>) -> Vec<String> {
    let by_id: BTreeMap<&str, &Doc> = task.docs.iter().map(|doc| (doc.id.as_str(), doc)).collect();
    let mut selected = Vec::new();
    let mut used = 0usize;
    for id in ordered {
        let Some(doc) = by_id.get(id.as_str()) else {
            continue;
        };
        let cost = estimate_tokens(&doc.text);
        if used + cost > BUDGET_TOKENS {
            continue;
        }
        used += cost;
        selected.push(id);
    }
    selected
}

fn select(strategy: &str, task: &Task, graph: &MemoryGraph, bm25: &[String]) -> Vec<String> {
    let seed = bm25
        .first()
        .map(String::as_str)
        .unwrap_or(task.anchor.as_str());
    let ordered = match strategy {
        "bm25" => bm25.to_vec(),
        "tfidf-dense" => dense_order(task),
        "bm25-tfidf-rrf" => hybrid_order(task),
        "graph-1hop" => one_hop_order(graph, seed),
        "graph-bfs" => bfs_order(graph, seed),
        "ccos-query-region" => region_order(graph, seed),
        "ccos-workspace-anchor" => region_order(graph, &task.anchor),
        _ => Vec::new(),
    };
    strict_budget(task, ordered)
}

fn score(task: &Task, selected: &[String]) -> (bool, f64, usize) {
    let selected_set: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
    let covered = task
        .required
        .iter()
        .filter(|id| selected_set.contains(id.as_str()))
        .count();
    let coverage = covered as f64 / task.required.len() as f64;
    let token_by_id: BTreeMap<&str, usize> = task
        .docs
        .iter()
        .map(|doc| (doc.id.as_str(), estimate_tokens(&doc.text)))
        .collect();
    let tokens = selected
        .iter()
        .filter_map(|id| token_by_id.get(id.as_str()))
        .sum();
    (covered == task.required.len(), coverage, tokens)
}

fn main() {
    let mut rows = Vec::new();
    for diameter in 1..=4u32 {
        let mut acc: BTreeMap<&'static str, Acc> = STRATEGIES
            .iter()
            .map(|(strategy, _)| (*strategy, Acc::default()))
            .collect();

        for task_no in 0..TASKS_PER_DIAMETER {
            let task = build_task(task_no + diameter as usize * 10_000, diameter);
            let graph = build_graph(&task);
            let bm25 = bm25_order(&task);
            for (strategy, _) in STRATEGIES {
                let selected = select(strategy, &task, &graph, &bm25);
                let (full, coverage, tokens) = score(&task, &selected);
                let tally = acc
                    .get_mut(strategy)
                    .expect("every strategy has an accumulator");
                tally.tasks += 1;
                tally.fully_covered += usize::from(full);
                tally.coverage_sum += coverage;
                tally.tokens_sum += tokens;
            }
        }

        for (strategy, assisted) in STRATEGIES {
            let tally = acc[&strategy];
            rows.push(BenchmarkRow {
                diameter,
                strategy,
                assisted_anchor: assisted,
                tasks: tally.tasks,
                full_evidence_rate: tally.fully_covered as f64 / tally.tasks as f64,
                mean_required_coverage: tally.coverage_sum / tally.tasks as f64,
                mean_estimated_tokens: tally.tokens_sum as f64 / tally.tasks as f64,
            });
        }
    }

    let report = BenchmarkReport {
        schema_version: SCHEMA_VERSION,
        claim_scope:
            "retrieval/selection necessary condition only; not end-to-end LLM answer quality",
        token_budget_kind: "ceil(chars/4) estimate; not a provider tokenizer count",
        budget_tokens: BUDGET_TOKENS,
        tasks_per_diameter: TASKS_PER_DIAMETER,
        decoys_per_task: DECOYS,
        rows,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("benchmark report is serializable")
    );
}

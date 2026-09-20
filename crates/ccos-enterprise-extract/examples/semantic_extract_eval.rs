//! Frozen synthetic regression evaluation. Not an independent quality holdout.
use ccos_enterprise_extract::semantic::{extract_relations, SEMANTIC_RULE_VERSION};
use ccos_enterprise_ingest::RawArtifact;
use ccos_enterprise_knowledge_model::{AssertionKind, SourceId, TenantId};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct Relation {
    subject: String,
    relation: String,
    polarity: String,
    object: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    language: String,
    text: String,
    expected: Vec<Relation>,
}
fn ratio(a: usize, b: usize) -> Option<f64> {
    if b == 0 {
        None
    } else {
        Some(a as f64 / b as f64)
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn git(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("git").args(args).output()?;
    if !out.status.success() {
        return Err("git metadata unavailable".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: semantic_extract_eval FIXTURE.jsonl".into());
    }
    let data = std::fs::read(&args[1])?;
    if data.len() > 4 * 1024 * 1024 {
        return Err("fixture too large".into());
    }
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    let (mut tp, mut fp, mut fn_, mut emitted, mut abstained) = (0, 0, 0, 0, 0);
    let mut runtimes = Vec::new();
    for line in std::str::from_utf8(&data)?
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let case: Case = serde_json::from_str(line)?;
        if case.id.is_empty()
            || !ids.insert(case.id.clone())
            || !matches!(case.language.as_str(), "en" | "fr")
        {
            return Err("invalid/duplicate case identity or language".into());
        }
        let expected: BTreeSet<_> = case.expected.iter().cloned().collect();
        if expected.len() != case.expected.len() {
            return Err("duplicate gold relation".into());
        }
        if expected.iter().any(|r| {
            !matches!(
                r.relation.as_str(),
                "works_for" | "located_in" | "depends_on"
            ) || !matches!(r.polarity.as_str(), "affirmed" | "negated")
        }) {
            return Err("invalid gold relation".into());
        }
        let raw = RawArtifact {
            tenant: TenantId::new("evaluation").unwrap(),
            source_id: SourceId::new(&case.id),
            virtual_uri: format!("fixture://{}", case.id),
            media_type: "text/plain".into(),
            content_hash: digest(case.text.as_bytes()),
            bytes: case.text.as_bytes().to_vec(),
        };
        let started = std::time::Instant::now();
        let batch = extract_relations(&raw)?;
        let elapsed = started.elapsed().as_nanos() as u64;
        runtimes.push(elapsed);
        for c in &batch.candidates {
            if c.kind() != AssertionKind::Observation
                || c.evidence().content_hash.as_deref() != Some(raw.content_hash.as_str())
            {
                return Err("candidate authority/hash invariant".into());
            }
            for m in [c.subject(), c.object()] {
                if raw.bytes.get(m.span().start..m.span().end) != Some(m.text().as_bytes()) {
                    return Err("mention span integrity failure".into());
                }
            }
        }
        let predicted: BTreeSet<_> = batch
            .candidates
            .iter()
            .map(|c| Relation {
                subject: c.subject().text().into(),
                relation: c.relation().as_str().into(),
                polarity: c.polarity().as_str().into(),
                object: c.object().text().into(),
            })
            .collect();
        let hits = predicted.intersection(&expected).count();
        let false_positives = predicted.difference(&expected).count();
        let missed = expected.difference(&predicted).count();
        tp += hits;
        fp += false_positives;
        fn_ += missed;
        emitted += usize::from(!predicted.is_empty());
        abstained += batch.abstentions.len();
        rows.push(json!({"id":case.id,"language":case.language,"tp":hits,"fp":false_positives,"fn":missed,"candidates":predicted.len(),"abstentions":batch.abstentions.len(),"latency_ns":elapsed}));
    }
    if rows.is_empty() {
        return Err("empty evaluation fixture".into());
    }
    runtimes.sort_unstable();
    let percentile =
        |percent: usize| runtimes[(percent * runtimes.len()).div_ceil(100).saturating_sub(1)];
    let executable = std::fs::read(std::env::current_exe()?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version":1,"scope":"authored_synthetic_regression_not_independent_holdout","rule_version":SEMANTIC_RULE_VERSION,
            "fixture_sha256":digest(&data),"code_sha":git(&["rev-parse","HEAD"] )?,"source_dirty":!git(&["status","--porcelain"] )?.is_empty(),"binary_sha256":digest(&executable),
            "cases":rows.len(),"tp":tp,"fp":fp,"fn":fn_,"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn_),"f1":ratio(2*tp,2*tp+fp+fn_),"case_coverage":ratio(emitted,rows.len()),"abstained_units":abstained,
            "latency_ns":{"p50":percentile(50),"p95":percentile(95),"p99":percentile(99)},"rows":rows
        }))?
    );
    Ok(())
}

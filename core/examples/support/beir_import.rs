//! Strict BEIR import, completed before any retrieval index is constructed.
//!
//! JSONL records must be objects. IDs and text are required strings; only a
//! missing corpus title defaults to an empty string. Present null/non-string
//! titles are errors. Metadata fields are permitted but never used for ranking.
//! Text bytes and opaque, case-sensitive IDs are preserved, not normalized.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QrelImportStats {
    pub data_rows: usize,
    pub positive_rows: usize,
    pub non_positive_rows: usize,
    pub positive_queries: usize,
}

#[derive(Debug)]
pub struct BeirDataset {
    pub docs: Vec<String>,
    pub queries: HashMap<String, String>,
    pub qrels: HashMap<String, HashMap<u64, f64>>,
    pub qrel_stats: QrelImportStats,
}

#[derive(Deserialize)]
struct CorpusRow {
    #[serde(rename = "_id")]
    id: String,
    #[serde(default)]
    title: String,
    text: String,
}

#[derive(Deserialize)]
struct QueryRow {
    #[serde(rename = "_id")]
    id: String,
    text: String,
}

struct Corpus {
    docs: Vec<String>,
    ids: HashMap<String, u64>,
}

struct QrelImport {
    qrels: HashMap<String, HashMap<u64, f64>>,
    stats: QrelImportStats,
}

fn invalid(path: &Path, line: usize, detail: impl std::fmt::Display) -> String {
    format!("{}:{line}: {detail}", path.display())
}

fn check_id(id: &str, path: &Path, line: usize) -> Result<(), String> {
    if id.is_empty() || id.trim() != id || id.chars().any(char::is_control) {
        return Err(invalid(
            path,
            line,
            "ID must be non-empty, without surrounding whitespace or control characters",
        ));
    }
    Ok(())
}

fn json_rows<T: DeserializeOwned>(
    reader: impl BufRead,
    path: &Path,
    mut accept: impl FnMut(T, usize) -> Result<(), String>,
) -> Result<(), String> {
    let mut rows = 0;
    for (offset, line) in reader.lines().enumerate() {
        let number = offset + 1;
        let line = line.map_err(|error| invalid(path, number, error))?;
        if !line.trim_start().starts_with('{') {
            return Err(invalid(
                path,
                number,
                "expected a JSON object, not a blank or scalar row",
            ));
        }
        let row = serde_json::from_str(&line).map_err(|error| invalid(path, number, error))?;
        accept(row, number)?;
        rows += 1;
    }
    if rows == 0 {
        return Err(invalid(path, 1, "no records"));
    }
    Ok(())
}

fn parse_corpus(reader: impl BufRead, path: &Path) -> Result<Corpus, String> {
    let mut docs = Vec::new();
    let mut ids = HashMap::new();
    json_rows(reader, path, |row: CorpusRow, line| {
        check_id(&row.id, path, line)?;
        if row.title.trim().is_empty() && row.text.trim().is_empty() {
            return Err(invalid(
                path,
                line,
                "document title and text are both blank",
            ));
        }
        match ids.entry(row.id) {
            Entry::Occupied(entry) => {
                return Err(invalid(
                    path,
                    line,
                    format!("duplicate document ID {:?}", entry.key()),
                ));
            }
            Entry::Vacant(entry) => {
                let dense_id = u64::try_from(docs.len())
                    .map_err(|_| invalid(path, line, "too many documents for a u64 ID"))?;
                entry.insert(dense_id);
                // Preserve the existing title-space-text indexing convention.
                docs.push(format!("{} {}", row.title, row.text));
            }
        }
        Ok(())
    })?;
    Ok(Corpus { docs, ids })
}

fn parse_queries(reader: impl BufRead, path: &Path) -> Result<HashMap<String, String>, String> {
    let mut queries = HashMap::new();
    json_rows(reader, path, |row: QueryRow, line| {
        check_id(&row.id, path, line)?;
        if row.text.trim().is_empty() {
            return Err(invalid(path, line, "query text is blank"));
        }
        match queries.entry(row.id) {
            Entry::Occupied(entry) => {
                return Err(invalid(
                    path,
                    line,
                    format!("duplicate query ID {:?}", entry.key()),
                ));
            }
            Entry::Vacant(entry) => {
                entry.insert(row.text);
            }
        }
        Ok(())
    })?;
    Ok(queries)
}

fn parse_qrels(
    reader: impl BufRead,
    path: &Path,
    doc_ids: &HashMap<String, u64>,
    queries: &HashMap<String, String>,
) -> Result<QrelImport, String> {
    let mut lines = reader.lines();
    let header = lines
        .next()
        .ok_or_else(|| invalid(path, 1, "qrels file is empty"))?
        .map_err(|error| invalid(path, 1, error))?;
    if header != "query-id\tcorpus-id\tscore" {
        return Err(invalid(
            path,
            1,
            "expected exact query-id/corpus-id/score TSV header",
        ));
    }
    let mut qrels: HashMap<String, HashMap<u64, f64>> = HashMap::new();
    let mut seen = HashSet::new();
    let mut stats = QrelImportStats::default();
    for (offset, line) in lines.enumerate() {
        let number = offset + 2;
        let line = line.map_err(|error| invalid(path, number, error))?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err(invalid(path, number, "expected exactly three TSV fields"));
        }
        let (qid, did) = (fields[0], fields[1]);
        check_id(qid, path, number)?;
        check_id(did, path, number)?;
        if !queries.contains_key(qid) {
            return Err(invalid(path, number, format!("unknown query ID {qid:?}")));
        }
        let &doc = doc_ids
            .get(did)
            .ok_or_else(|| invalid(path, number, format!("unknown document ID {did:?}")))?;
        let gain: f64 = fields[2]
            .parse()
            .map_err(|_| invalid(path, number, "non-numeric relevance score"))?;
        if !gain.is_finite() {
            return Err(invalid(path, number, "non-finite relevance score"));
        }
        if !seen.insert((qid.to_string(), doc)) {
            return Err(invalid(
                path,
                number,
                format!("duplicate judgment: {qid:?}, {did:?}"),
            ));
        }
        stats.data_rows += 1;
        if gain > 0.0 {
            qrels.entry(qid.to_string()).or_default().insert(doc, gain);
            stats.positive_rows += 1;
        } else {
            stats.non_positive_rows += 1;
        }
    }
    if qrels.is_empty() {
        return Err(invalid(path, 1, "no positive relevance judgments"));
    }
    stats.positive_queries = qrels.len();
    Ok(QrelImport { qrels, stats })
}

fn open(path: &Path) -> Result<BufReader<File>, String> {
    File::open(path)
        .map(BufReader::new)
        .map_err(|error| format!("{}: cannot open input: {error}", path.display()))
}

/// Import the entire evaluation population or return its first error.
///
/// This module has no index or encoder dependency. Callers receive no partial
/// dataset and must not start indexing until this function succeeds. It streams
/// lines but retains the validated dataset; no total-RAM bound is claimed.
pub fn load_dataset(root: &Path) -> Result<BeirDataset, String> {
    let corpus_path = root.join("corpus.jsonl");
    let query_path = root.join("queries.jsonl");
    let qrel_path = root.join("qrels/test.tsv");
    let corpus = parse_corpus(open(&corpus_path)?, &corpus_path)?;
    let queries = parse_queries(open(&query_path)?, &query_path)?;
    let imported = parse_qrels(open(&qrel_path)?, &qrel_path, &corpus.ids, &queries)?;
    Ok(BeirDataset {
        docs: corpus.docs,
        queries,
        qrels: imported.qrels,
        qrel_stats: imported.stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"_id":"d1","title":"Title","text":"Body"}"#;
    const QUERY: &str = r#"{"_id":"q1","text":"Question"}"#;
    const HEADER: &str = "query-id\tcorpus-id\tscore\n";

    fn corpus(raw: &str) -> Result<Corpus, String> {
        parse_corpus(raw.as_bytes(), Path::new("corpus.jsonl"))
    }

    fn queries(raw: &str) -> Result<HashMap<String, String>, String> {
        parse_queries(raw.as_bytes(), Path::new("queries.jsonl"))
    }

    fn qrels(raw: &str) -> Result<QrelImport, String> {
        parse_qrels(
            raw.as_bytes(),
            Path::new("qrels/test.tsv"),
            &HashMap::from([("d1".into(), 0), ("d2".into(), 1)]),
            &HashMap::from([
                ("q1".into(), "Question".into()),
                ("q2".into(), "Other".into()),
            ]),
        )
    }

    #[test]
    fn optional_title_and_metadata_preserve_text_and_dense_ids() {
        let raw = format!(
            "{DOC}\n{{\"_id\":\"Doc/É:2\",\"text\":\"  preserved  \",\"metadata\":{{}}}}\n"
        );
        let parsed = corpus(&raw).unwrap();
        assert_eq!(parsed.ids["d1"], 0);
        assert_eq!(parsed.ids["Doc/É:2"], 1);
        assert_eq!(parsed.docs, vec!["Title Body", "   preserved  "]);
    }

    #[test]
    fn title_only_document_is_valid_but_text_field_remains_required() {
        assert!(corpus(r#"{"_id":"d1","title":"Title","text":""}"#).is_ok());
        assert!(corpus(r#"{"_id":"d1","title":"Title"}"#).is_err());
    }

    #[test]
    fn duplicate_document_id_is_an_error_not_an_overwrite() {
        let error = corpus(&format!("{DOC}\n{DOC}\n")).err().unwrap();
        assert!(error.contains("corpus.jsonl:2:"), "{error}");
        assert!(error.contains("duplicate document ID"), "{error}");
    }

    #[test]
    fn duplicate_query_id_is_an_error_not_an_overwrite() {
        let error = queries(&format!("{QUERY}\n{QUERY}\n")).unwrap_err();
        assert!(error.contains("queries.jsonl:2:"), "{error}");
        assert!(error.contains("duplicate query ID"), "{error}");
    }

    #[test]
    fn required_text_and_id_fields_are_not_defaulted() {
        for raw in [
            r#"{"_id":"d1"}"#,
            r#"{"text":"Body"}"#,
            r#"{"_id":1,"text":"Body"}"#,
            r#"{"_id":null,"text":"Body"}"#,
            r#"{"_id":"d1","text":null}"#,
            r#"{"_id":"d1","text":42}"#,
        ] {
            assert!(corpus(raw).is_err(), "{raw}");
            assert!(queries(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn present_title_must_be_a_string() {
        for value in ["null", "42", "[]", "{}", "true"] {
            let raw = format!("{{\"_id\":\"d1\",\"title\":{value},\"text\":\"Body\"}}");
            assert!(corpus(&raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn blank_or_control_bearing_ids_are_rejected_without_normalization() {
        for id in ["", " ", " d1", "d1 ", "d\t1", "d\n1"] {
            let raw = serde_json::json!({"_id": id, "text": "Body"}).to_string();
            assert!(corpus(&raw).is_err(), "{id:?}");
            assert!(queries(&raw).is_err(), "{id:?}");
        }
    }

    #[test]
    fn blank_records_empty_inputs_and_non_objects_are_rejected() {
        for raw in ["", "\n", "null", "[]", "42", "[\"id\",\"text\"]"] {
            assert!(corpus(raw).is_err(), "{raw:?}");
            assert!(queries(raw).is_err(), "{raw:?}");
        }
        assert!(corpus(&format!("{DOC}\n\n{DOC}"))
            .err()
            .unwrap()
            .contains(":2:"));
    }

    #[test]
    fn malformed_json_reports_its_actual_line() {
        let error = queries(&format!("{QUERY}\n{{bad}}\n")).unwrap_err();
        assert!(error.contains("queries.jsonl:2:"), "{error}");
    }

    #[test]
    fn repeated_authoritative_json_fields_are_rejected() {
        for raw in [
            r#"{"_id":"d1","_id":"d2","text":"Body"}"#,
            r#"{"_id":"d1","text":"first","text":"second"}"#,
        ] {
            assert!(corpus(raw).is_err(), "{raw}");
            assert!(queries(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn blank_document_and_query_text_cannot_be_silently_indexed() {
        assert!(corpus(r#"{"_id":"d1","text":" "}"#).is_err());
        assert!(queries(r#"{"_id":"q1","text":" "}"#).is_err());
    }

    #[test]
    fn strict_qrels_count_positive_and_non_positive_rows() {
        let imported = qrels(&format!("{HEADER}q1\td1\t2\nq1\td2\t0\nq2\td2\t-1\n")).unwrap();
        assert_eq!(
            imported.stats,
            QrelImportStats {
                data_rows: 3,
                positive_rows: 1,
                non_positive_rows: 2,
                positive_queries: 1,
            }
        );
        assert_eq!(imported.qrels["q1"][&0], 2.0);
        assert_eq!(imported.qrels.len(), 1);
    }

    #[test]
    fn strict_qrels_reject_unknown_references_even_for_non_positive_scores() {
        for row in [
            "unknown\td1\t1",
            "q1\tunknown\t1",
            "q1\tunknown\t0",
            "unknown\td1\t-1",
        ] {
            assert!(qrels(&format!("{HEADER}{row}\n")).is_err(), "{row}");
        }
    }

    #[test]
    fn strict_qrels_reject_duplicate_judgments_of_any_sign() {
        for second in ["1", "0", "-1"] {
            assert!(qrels(&format!("{HEADER}q1\td1\t1\nq1\td1\t{second}\n")).is_err());
        }
        assert!(qrels(&format!("{HEADER}q1\td1\t0\nq1\td1\t1\n")).is_err());
    }

    #[test]
    fn strict_qrels_require_header_fields_finite_scores_and_positive_judgments() {
        for raw in ["", "wrong\nq1\td1\t1\n", HEADER] {
            assert!(qrels(raw).is_err(), "{raw:?}");
        }
        for row in [
            "",
            "q1\td1",
            "q1\td1\t1\textra",
            "\td1\t1",
            "q1\t\t1",
            "q1\td1\tNaN",
            "q1\td1\tinf",
            "q1\td1\t-Inf",
            "q1\td1\tbad",
            "q1\td1\t0",
            "q1\td1\t-1",
        ] {
            let error = qrels(&format!("{HEADER}{row}\n")).err().unwrap();
            assert!(error.contains("qrels/test.tsv:"), "{error}");
        }
    }

    #[test]
    fn crlf_and_final_line_without_newline_are_supported() {
        assert_eq!(corpus(&format!("{DOC}\r\n")).unwrap().docs.len(), 1);
        assert_eq!(queries(QUERY).unwrap()["q1"], "Question");
        assert_eq!(
            qrels("query-id\tcorpus-id\tscore\r\nq1\td1\t1")
                .unwrap()
                .stats
                .data_rows,
            1
        );
    }
}

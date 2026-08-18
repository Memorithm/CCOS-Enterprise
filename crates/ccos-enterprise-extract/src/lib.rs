//! Deterministic structural extraction for parsed Knowledge Plane artifacts.
//!
//! P2a emits record candidates, not canonical entities/facts. Every candidate is an
//! [`AssertionKind::Observation`] and carries fine-grained evidence into immutable raw
//! source bytes. Entity resolution and authority promotion are intentionally later gates.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_ingest::RawArtifact;
use ccos_enterprise_knowledge_model::{
    AssertionKind, EvidenceId, EvidenceRecord, SourceId, TenantId,
};
use ccos_enterprise_parse::{parse, ParseError, ParsedDocument, ParsedUnit, ParsedUnitKind};
use sha2::{Digest, Sha256};

pub const EXTRACTION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateId(pub String);

impl CandidateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExtractedValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Json(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCandidate {
    pub id: CandidateId,
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub unit_ordinal: usize,
    pub record_index: usize,
    pub kind: AssertionKind,
    pub evidence: EvidenceRecord,
    pub attributes: BTreeMap<String, ExtractedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionBatch {
    pub contract_version: u32,
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub raw_content_hash: String,
    pub candidates: Vec<RecordCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    Parse(String),
    InvalidJson {
        unit: usize,
        detail: String,
    },
    JsonTopLevelUnsupported {
        unit: usize,
    },
    CsvMissingHeader,
    CsvEmptyHeader {
        column: usize,
    },
    CsvDuplicateHeader(String),
    CsvMalformed {
        unit: usize,
        detail: String,
    },
    CsvWidth {
        unit: usize,
        expected: usize,
        found: usize,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(detail) => write!(f, "parse failed: {detail}"),
            Self::InvalidJson { unit, detail } => {
                write!(f, "unit {unit} contains invalid JSON: {detail}")
            }
            Self::JsonTopLevelUnsupported { unit } => write!(
                f,
                "unit {unit} JSON top level is not an object or object array"
            ),
            Self::CsvMissingHeader => f.write_str("CSV source has no header record"),
            Self::CsvEmptyHeader { column } => write!(f, "CSV header column {column} is empty"),
            Self::CsvDuplicateHeader(header) => {
                write!(f, "CSV header {header:?} appears more than once")
            }
            Self::CsvMalformed { unit, detail } => {
                write!(f, "CSV record {unit} is malformed: {detail}")
            }
            Self::CsvWidth {
                unit,
                expected,
                found,
            } => write!(
                f,
                "CSV record {unit} has {found} fields; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<ParseError> for ExtractError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value.to_string())
    }
}

pub fn extract(raw: &RawArtifact) -> Result<ExtractionBatch, ExtractError> {
    let parsed = parse(raw)?;
    let candidates = match raw.media_type.as_str() {
        "application/json" => extract_json_document(raw, &parsed)?,
        "application/x-ndjson" => extract_ndjson(raw, &parsed)?,
        "text/csv" => extract_csv(raw, &parsed)?,
        "text/plain" | "text/markdown" => Vec::new(),
        _ => Vec::new(),
    };
    Ok(ExtractionBatch {
        contract_version: EXTRACTION_CONTRACT_VERSION,
        tenant: raw.tenant.clone(),
        source_id: raw.source_id.clone(),
        raw_content_hash: raw.content_hash.clone(),
        candidates,
    })
}

fn extract_json_document(
    raw: &RawArtifact,
    parsed: &ParsedDocument,
) -> Result<Vec<RecordCandidate>, ExtractError> {
    let unit = &parsed.units[0];
    let value: serde_json::Value =
        serde_json::from_str(&unit.normalized_text).map_err(|error| ExtractError::InvalidJson {
            unit: unit.ordinal,
            detail: error.to_string(),
        })?;
    match value {
        serde_json::Value::Object(map) => Ok(vec![candidate_from_object(raw, unit, 0, map)]),
        serde_json::Value::Array(values) => {
            let mut candidates = Vec::with_capacity(values.len());
            for (record_index, value) in values.into_iter().enumerate() {
                let serde_json::Value::Object(map) = value else {
                    return Err(ExtractError::JsonTopLevelUnsupported { unit: unit.ordinal });
                };
                candidates.push(candidate_from_object(raw, unit, record_index, map));
            }
            Ok(candidates)
        }
        _ => Err(ExtractError::JsonTopLevelUnsupported { unit: unit.ordinal }),
    }
}

fn extract_ndjson(
    raw: &RawArtifact,
    parsed: &ParsedDocument,
) -> Result<Vec<RecordCandidate>, ExtractError> {
    let mut candidates = Vec::with_capacity(parsed.units.len());
    for unit in &parsed.units {
        let value: serde_json::Value =
            serde_json::from_str(&unit.normalized_text).map_err(|error| {
                ExtractError::InvalidJson {
                    unit: unit.ordinal,
                    detail: error.to_string(),
                }
            })?;
        let serde_json::Value::Object(map) = value else {
            return Err(ExtractError::JsonTopLevelUnsupported { unit: unit.ordinal });
        };
        candidates.push(candidate_from_object(raw, unit, 0, map));
    }
    Ok(candidates)
}

fn candidate_from_object(
    raw: &RawArtifact,
    unit: &ParsedUnit,
    record_index: usize,
    map: serde_json::Map<String, serde_json::Value>,
) -> RecordCandidate {
    let attributes = map
        .into_iter()
        .map(|(key, value)| (key, extracted_value(value)))
        .collect();
    build_candidate(raw, unit, record_index, attributes)
}

fn extracted_value(value: serde_json::Value) -> ExtractedValue {
    match value {
        serde_json::Value::Null => ExtractedValue::Null,
        serde_json::Value::Bool(value) => ExtractedValue::Bool(value),
        serde_json::Value::Number(value) => ExtractedValue::Number(value.to_string()),
        serde_json::Value::String(value) => ExtractedValue::String(value),
        nested @ (serde_json::Value::Array(_) | serde_json::Value::Object(_)) => {
            let mut canonical = String::new();
            write_canonical_json(&nested, &mut canonical);
            ExtractedValue::Json(canonical)
        }
    }
}

fn extract_csv(
    raw: &RawArtifact,
    parsed: &ParsedDocument,
) -> Result<Vec<RecordCandidate>, ExtractError> {
    let Some(header_unit) = parsed.units.first() else {
        return Err(ExtractError::CsvMissingHeader);
    };
    let headers = parse_csv_fields(&header_unit.normalized_text, header_unit.ordinal)?;
    let mut seen = BTreeSet::new();
    let mut canonical_headers = Vec::with_capacity(headers.len());
    for (column, header) in headers.into_iter().enumerate() {
        let header = header.trim().to_owned();
        if header.is_empty() {
            return Err(ExtractError::CsvEmptyHeader { column });
        }
        if !seen.insert(header.clone()) {
            return Err(ExtractError::CsvDuplicateHeader(header));
        }
        canonical_headers.push(header);
    }

    let mut candidates = Vec::with_capacity(parsed.units.len().saturating_sub(1));
    for unit in parsed.units.iter().skip(1) {
        let fields = parse_csv_fields(&unit.normalized_text, unit.ordinal)?;
        if fields.len() != canonical_headers.len() {
            return Err(ExtractError::CsvWidth {
                unit: unit.ordinal,
                expected: canonical_headers.len(),
                found: fields.len(),
            });
        }
        let attributes = canonical_headers
            .iter()
            .cloned()
            .zip(fields.into_iter().map(ExtractedValue::String))
            .collect();
        candidates.push(build_candidate(raw, unit, 0, attributes));
    }
    Ok(candidates)
}

fn parse_csv_fields(record: &str, unit: usize) -> Result<Vec<String>, ExtractError> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = record.chars().peekable();
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut closed_quote = false;

    while let Some(character) = chars.next() {
        if in_quotes {
            if character == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                    closed_quote = true;
                }
            } else {
                field.push(character);
            }
            continue;
        }

        if closed_quote {
            if character == ',' {
                fields.push(std::mem::take(&mut field));
                at_field_start = true;
                closed_quote = false;
                continue;
            }
            return Err(ExtractError::CsvMalformed {
                unit,
                detail: "characters after closing quote before delimiter".into(),
            });
        }

        match character {
            ',' => {
                fields.push(std::mem::take(&mut field));
                at_field_start = true;
            }
            '"' if at_field_start => {
                in_quotes = true;
                at_field_start = false;
            }
            '"' => {
                return Err(ExtractError::CsvMalformed {
                    unit,
                    detail: "quote inside unquoted field".into(),
                });
            }
            other => {
                field.push(other);
                at_field_start = false;
            }
        }
    }

    if in_quotes {
        return Err(ExtractError::CsvMalformed {
            unit,
            detail: "unterminated quoted field".into(),
        });
    }
    fields.push(field);
    Ok(fields)
}

fn build_candidate(
    raw: &RawArtifact,
    unit: &ParsedUnit,
    record_index: usize,
    attributes: BTreeMap<String, ExtractedValue>,
) -> RecordCandidate {
    let locator = unit.evidence_locator();
    let evidence_id = evidence_id(raw, &locator);
    let evidence = EvidenceRecord {
        id: evidence_id,
        tenant: raw.tenant.clone(),
        source: raw.source_id.clone(),
        locator: Some(locator),
        content_hash: Some(raw.content_hash.clone()),
    };

    let mut hasher = Sha256::new();
    hasher.update(raw.tenant.0.as_bytes());
    hasher.update([0]);
    hasher.update(raw.source_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(raw.content_hash.as_bytes());
    hasher.update([0]);
    hasher.update(unit.ordinal.to_le_bytes());
    hasher.update(record_index.to_le_bytes());
    hasher.update(unit.content_hash.as_bytes());
    let id = CandidateId(format!(
        "candidate:record:{}",
        hex_lower(&hasher.finalize())
    ));

    RecordCandidate {
        id,
        tenant: raw.tenant.clone(),
        source_id: raw.source_id.clone(),
        unit_ordinal: unit.ordinal,
        record_index,
        kind: AssertionKind::Observation,
        evidence,
        attributes,
    }
}

fn evidence_id(raw: &RawArtifact, locator: &str) -> EvidenceId {
    let mut hasher = Sha256::new();
    hasher.update(raw.tenant.0.as_bytes());
    hasher.update([0]);
    hasher.update(raw.source_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(raw.content_hash.as_bytes());
    hasher.update([0]);
    hasher.update(locator.as_bytes());
    EvidenceId::new(format!("evidence:unit:{}", hex_lower(&hasher.finalize())))
}

fn write_canonical_json(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(value) => output.push_str(&value.to_string()),
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value).expect("serializing a JSON string cannot fail"),
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("serializing a JSON object key cannot fail"),
                );
                output.push(':');
                write_canonical_json(&values[key], output);
            }
            output.push('}');
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_knowledge_model::{SourceId, TenantId};

    fn raw(media_type: &str, bytes: &[u8]) -> RawArtifact {
        let digest = Sha256::digest(bytes);
        RawArtifact {
            tenant: TenantId("acme".into()),
            source_id: SourceId::from("source:test"),
            virtual_uri: "fs://dataset/test".into(),
            media_type: media_type.into(),
            content_hash: format!("sha256:{}", hex_lower(&digest)),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn json_object_becomes_observation_record_with_sorted_attributes() {
        let batch = extract(&raw(
            "application/json",
            br#"{"name":"Acme","active":true,"nested":{"z":2,"a":1}}"#,
        ))
        .unwrap();
        assert_eq!(batch.candidates.len(), 1);
        let candidate = &batch.candidates[0];
        assert_eq!(candidate.kind, AssertionKind::Observation);
        assert_eq!(
            candidate.attributes["name"],
            ExtractedValue::String("Acme".into())
        );
        assert_eq!(candidate.attributes["active"], ExtractedValue::Bool(true));
        assert_eq!(
            candidate.attributes["nested"],
            ExtractedValue::Json(r#"{"a":1,"z":2}"#.into())
        );
    }

    #[test]
    fn json_array_records_have_distinct_candidate_ids() {
        let batch = extract(&raw("application/json", br#"[{"id":1},{"id":2}]"#)).unwrap();
        assert_eq!(batch.candidates.len(), 2);
        assert_ne!(batch.candidates[0].id, batch.candidates[1].id);
        assert_eq!(
            batch.candidates[0].evidence.id,
            batch.candidates[1].evidence.id
        );
    }

    #[test]
    fn ndjson_evidence_is_bound_to_each_raw_record_span() {
        let artifact = raw("application/x-ndjson", b"{\"id\":1}\r\n{\"id\":2}\r\n");
        let batch = extract(&artifact).unwrap();
        assert_eq!(batch.candidates.len(), 2);
        assert_ne!(
            batch.candidates[0].evidence.id,
            batch.candidates[1].evidence.id
        );
        assert_eq!(
            batch.candidates[0].evidence.locator.as_deref(),
            Some("bytes:0-8")
        );
        assert_eq!(
            batch.candidates[1].evidence.locator.as_deref(),
            Some("bytes:10-18")
        );
    }

    #[test]
    fn csv_header_maps_quoted_fields_and_newlines() {
        let batch = extract(&raw(
            "text/csv",
            b"id,text\r\n1,\"hello, world\"\r\n2,\"two\r\nlines\"\r\n",
        ))
        .unwrap();
        assert_eq!(batch.candidates.len(), 2);
        assert_eq!(
            batch.candidates[0].attributes["id"],
            ExtractedValue::String("1".into())
        );
        assert_eq!(
            batch.candidates[0].attributes["text"],
            ExtractedValue::String("hello, world".into())
        );
        assert_eq!(
            batch.candidates[1].attributes["text"],
            ExtractedValue::String("two\nlines".into())
        );
    }

    #[test]
    fn csv_duplicate_headers_fail_closed() {
        assert_eq!(
            extract(&raw("text/csv", b"id,id\n1,2\n")),
            Err(ExtractError::CsvDuplicateHeader("id".into()))
        );
    }

    #[test]
    fn unstructured_text_is_not_invented_into_entities() {
        let batch = extract(&raw("text/plain", b"Alice works at Acme\n")).unwrap();
        assert!(batch.candidates.is_empty());
    }
}

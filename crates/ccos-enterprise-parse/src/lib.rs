//! Deterministic source-span parsing for Knowledge Plane artifacts.
//!
//! Parsing calls the P1b normalizer internally, but every emitted unit retains an exact
//! byte span into the immutable P1a raw source. Later extraction can therefore cite a
//! raw evidence locator rather than a position in rewritten normalized text.

#![forbid(unsafe_code)]

use std::fmt;

use ccos_enterprise_ingest::RawArtifact;
use ccos_enterprise_knowledge_model::{SourceId, TenantId};
use ccos_enterprise_normalize::{normalize, NormalizeError, NormalizedArtifact};
use sha2::{Digest, Sha256};

pub const PARSE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn locator(self) -> String {
        format!("bytes:{}-{}", self.start, self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedUnitKind {
    TextLine,
    MarkdownLine,
    JsonDocument,
    NdjsonRecord,
    CsvRecord,
}

impl ParsedUnitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextLine => "text-line",
            Self::MarkdownLine => "markdown-line",
            Self::JsonDocument => "json-document",
            Self::NdjsonRecord => "ndjson-record",
            Self::CsvRecord => "csv-record",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUnit {
    pub ordinal: usize,
    pub kind: ParsedUnitKind,
    pub raw_span: ByteSpan,
    pub normalized_text: String,
    pub content_hash: String,
}

impl ParsedUnit {
    pub fn evidence_locator(&self) -> String {
        self.raw_span.locator()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDocument {
    pub contract_version: u32,
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub virtual_uri: String,
    pub media_type: String,
    pub raw_content_hash: String,
    pub normalized_content_hash: String,
    pub units: Vec<ParsedUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Normalize(String),
    NormalizationShapeMismatch,
    InvalidNormalizedUtf8,
    UnterminatedCsvQuote { raw_offset: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normalize(detail) => write!(f, "normalization failed: {detail}"),
            Self::NormalizationShapeMismatch => {
                f.write_str("normalized record framing no longer matches raw source framing")
            }
            Self::InvalidNormalizedUtf8 => f.write_str("normalized artifact is not valid UTF-8"),
            Self::UnterminatedCsvQuote { raw_offset } => {
                write!(
                    f,
                    "CSV quoted field is not terminated near raw byte {raw_offset}"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<NormalizeError> for ParseError {
    fn from(value: NormalizeError) -> Self {
        Self::Normalize(value.to_string())
    }
}

pub fn parse(raw: &RawArtifact) -> Result<ParsedDocument, ParseError> {
    let normalized = normalize(raw)?;
    let units = match raw.media_type.as_str() {
        "text/plain" => parse_lines(raw, &normalized, ParsedUnitKind::TextLine)?,
        "text/markdown" => parse_lines(raw, &normalized, ParsedUnitKind::MarkdownLine)?,
        "application/json" => parse_json_document(raw, &normalized)?,
        "application/x-ndjson" => parse_ndjson(raw, &normalized)?,
        "text/csv" => parse_csv_records(raw, &normalized)?,
        _ => return Err(ParseError::NormalizationShapeMismatch),
    };

    Ok(ParsedDocument {
        contract_version: PARSE_CONTRACT_VERSION,
        tenant: raw.tenant.clone(),
        source_id: raw.source_id.clone(),
        virtual_uri: raw.virtual_uri.clone(),
        media_type: raw.media_type.clone(),
        raw_content_hash: raw.content_hash.clone(),
        normalized_content_hash: normalized.manifest.output_content_hash,
        units,
    })
}

fn parse_json_document(
    raw: &RawArtifact,
    normalized: &NormalizedArtifact,
) -> Result<Vec<ParsedUnit>, ParseError> {
    let text =
        std::str::from_utf8(&normalized.bytes).map_err(|_| ParseError::InvalidNormalizedUtf8)?;
    let start = if raw.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        3
    } else {
        0
    };
    Ok(vec![unit(
        0,
        ParsedUnitKind::JsonDocument,
        ByteSpan {
            start,
            end: raw.bytes.len(),
        },
        text.to_owned(),
    )])
}

fn parse_lines(
    raw: &RawArtifact,
    normalized: &NormalizedArtifact,
    kind: ParsedUnitKind,
) -> Result<Vec<ParsedUnit>, ParseError> {
    let raw_spans = line_spans(&raw.bytes);
    let normalized_spans = line_spans(&normalized.bytes);
    if raw_spans.len() != normalized_spans.len() {
        return Err(ParseError::NormalizationShapeMismatch);
    }
    let normalized_text =
        std::str::from_utf8(&normalized.bytes).map_err(|_| ParseError::InvalidNormalizedUtf8)?;
    let mut units = Vec::with_capacity(raw_spans.len());
    for (ordinal, (raw_span, normalized_span)) in
        raw_spans.into_iter().zip(normalized_spans).enumerate()
    {
        units.push(unit(
            ordinal,
            kind,
            raw_span,
            normalized_text[normalized_span.start..normalized_span.end].to_owned(),
        ));
    }
    Ok(units)
}

fn parse_ndjson(
    raw: &RawArtifact,
    normalized: &NormalizedArtifact,
) -> Result<Vec<ParsedUnit>, ParseError> {
    let raw_spans = line_spans(&raw.bytes);
    let normalized_spans = line_spans(&normalized.bytes);
    if raw_spans.len() != normalized_spans.len() {
        return Err(ParseError::NormalizationShapeMismatch);
    }
    let normalized_text =
        std::str::from_utf8(&normalized.bytes).map_err(|_| ParseError::InvalidNormalizedUtf8)?;
    let mut units = Vec::new();
    for (raw_span, normalized_span) in raw_spans.into_iter().zip(normalized_spans) {
        let text = &normalized_text[normalized_span.start..normalized_span.end];
        if text.is_empty() {
            continue;
        }
        units.push(unit(
            units.len(),
            ParsedUnitKind::NdjsonRecord,
            raw_span,
            text.to_owned(),
        ));
    }
    Ok(units)
}

fn parse_csv_records(
    raw: &RawArtifact,
    normalized: &NormalizedArtifact,
) -> Result<Vec<ParsedUnit>, ParseError> {
    let raw_spans = csv_record_spans(&raw.bytes)?;
    let normalized_spans = csv_record_spans(&normalized.bytes)?;
    if raw_spans.len() != normalized_spans.len() {
        return Err(ParseError::NormalizationShapeMismatch);
    }
    let normalized_text =
        std::str::from_utf8(&normalized.bytes).map_err(|_| ParseError::InvalidNormalizedUtf8)?;
    let mut units = Vec::with_capacity(raw_spans.len());
    for (ordinal, (raw_span, normalized_span)) in
        raw_spans.into_iter().zip(normalized_spans).enumerate()
    {
        units.push(unit(
            ordinal,
            ParsedUnitKind::CsvRecord,
            raw_span,
            normalized_text[normalized_span.start..normalized_span.end].to_owned(),
        ));
    }
    Ok(units)
}

fn unit(
    ordinal: usize,
    kind: ParsedUnitKind,
    raw_span: ByteSpan,
    normalized_text: String,
) -> ParsedUnit {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(normalized_text.as_bytes());
    ParsedUnit {
        ordinal,
        kind,
        raw_span,
        content_hash: format!("sha256:{}", hex_lower(&hasher.finalize())),
        normalized_text,
    }
}

/// Logical line spans excluding BOM and line terminators. A trailing line terminator does
/// not manufacture an empty record; an explicit empty line between terminators does.
fn line_spans(bytes: &[u8]) -> Vec<ByteSpan> {
    let mut start = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        3
    } else {
        0
    };
    let mut index = start;
    let mut spans = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                spans.push(ByteSpan { start, end: index });
                index += 1;
                if index < bytes.len() && bytes[index] == b'\n' {
                    index += 1;
                }
                start = index;
            }
            b'\n' => {
                spans.push(ByteSpan { start, end: index });
                index += 1;
                start = index;
            }
            _ => index += 1,
        }
    }
    if start < bytes.len() {
        spans.push(ByteSpan {
            start,
            end: bytes.len(),
        });
    }
    spans
}

/// RFC-4180-style record framing. This deliberately stops at records: field typing and
/// header/schema interpretation belong to a later semantic parsing layer.
fn csv_record_spans(bytes: &[u8]) -> Result<Vec<ByteSpan>, ParseError> {
    let mut start = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        3
    } else {
        0
    };
    let mut index = start;
    let mut in_quotes = false;
    let mut spans = Vec::new();

    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                if in_quotes && index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                    index += 2;
                    continue;
                }
                in_quotes = !in_quotes;
                index += 1;
            }
            b'\r' | b'\n' if !in_quotes => {
                spans.push(ByteSpan { start, end: index });
                if bytes[index] == b'\r' && index + 1 < bytes.len() && bytes[index + 1] == b'\n' {
                    index += 2;
                } else {
                    index += 1;
                }
                start = index;
            }
            _ => index += 1,
        }
    }

    if in_quotes {
        return Err(ParseError::UnterminatedCsvQuote { raw_offset: start });
    }
    if start < bytes.len() {
        spans.push(ByteSpan {
            start,
            end: bytes.len(),
        });
    }
    Ok(spans)
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
    fn text_lines_point_back_to_exact_raw_bytes() {
        let artifact = raw("text/plain", b"\xef\xbb\xbfalpha\r\nbeta\r");
        let parsed = parse(&artifact).unwrap();
        assert_eq!(parsed.units.len(), 2);
        assert_eq!(parsed.units[0].raw_span, ByteSpan { start: 3, end: 8 });
        assert_eq!(&artifact.bytes[3..8], b"alpha");
        assert_eq!(parsed.units[0].normalized_text, "alpha");
        assert_eq!(parsed.units[1].raw_span, ByteSpan { start: 10, end: 14 });
        assert_eq!(&artifact.bytes[10..14], b"beta");
    }

    #[test]
    fn json_is_one_canonical_unit_with_raw_document_span() {
        let artifact = raw("application/json", br#"{ "z": 0, "a": 1 }"#);
        let parsed = parse(&artifact).unwrap();
        assert_eq!(parsed.units.len(), 1);
        assert_eq!(parsed.units[0].kind, ParsedUnitKind::JsonDocument);
        assert_eq!(
            parsed.units[0].raw_span,
            ByteSpan {
                start: 0,
                end: artifact.bytes.len()
            }
        );
        assert_eq!(parsed.units[0].normalized_text, r#"{"a":1,"z":0}"#);
    }

    #[test]
    fn ndjson_records_keep_raw_line_spans_and_skip_blank_records() {
        let artifact = raw(
            "application/x-ndjson",
            b"{\"b\":2,\"a\":1}\r\n\r\n{\"z\":0}\r\n",
        );
        let parsed = parse(&artifact).unwrap();
        assert_eq!(parsed.units.len(), 2);
        assert_eq!(parsed.units[0].normalized_text, r#"{"a":1,"b":2}"#);
        assert_eq!(parsed.units[1].normalized_text, r#"{"z":0}"#);
        assert_eq!(
            &artifact.bytes[parsed.units[1].raw_span.start..parsed.units[1].raw_span.end],
            b"{\"z\":0}"
        );
    }

    #[test]
    fn csv_quoted_newline_stays_inside_one_record() {
        let artifact = raw("text/csv", b"id,text\r\n1,\"hello\r\nworld\"\r\n2,end\r\n");
        let parsed = parse(&artifact).unwrap();
        assert_eq!(parsed.units.len(), 3);
        assert_eq!(parsed.units[1].kind, ParsedUnitKind::CsvRecord);
        assert_eq!(parsed.units[1].normalized_text, "1,\"hello\nworld\"");
    }

    #[test]
    fn unterminated_csv_quote_fails_closed() {
        let artifact = raw("text/csv", b"id,text\n1,\"broken\n");
        assert!(matches!(
            parse(&artifact),
            Err(ParseError::UnterminatedCsvQuote { .. })
        ));
    }
}

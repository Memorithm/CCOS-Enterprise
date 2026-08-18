//! Deterministic normalization of immutable ingestion artifacts.
//!
//! Normalization never replaces source evidence. [`NormalizedArtifact`] carries the raw
//! input hash and a distinct normalized output hash so later parsers/extractors can cite
//! the immutable source while consuming a stable representation.

#![forbid(unsafe_code)]

use std::fmt;

use ccos_enterprise_ingest::RawArtifact;
use ccos_enterprise_knowledge_model::{SourceId, TenantId};
use sha2::{Digest, Sha256};

pub const NORMALIZATION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationAlgorithm {
    TextV1,
    JsonCanonicalV1,
    NdjsonCanonicalV1,
}

impl NormalizationAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextV1 => "text-v1",
            Self::JsonCanonicalV1 => "json-canonical-v1",
            Self::NdjsonCanonicalV1 => "ndjson-canonical-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationManifest {
    pub contract_version: u32,
    pub algorithm: NormalizationAlgorithm,
    pub input_content_hash: String,
    pub output_content_hash: String,
    pub media_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedArtifact {
    pub tenant: TenantId,
    pub source_id: SourceId,
    pub virtual_uri: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub manifest: NormalizationManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    InputHashMismatch { declared: String, actual: String },
    UnsupportedMediaType(String),
    InvalidUtf8,
    InvalidJson(String),
    InvalidNdjson { line: usize, detail: String },
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputHashMismatch { declared, actual } => {
                write!(
                    f,
                    "raw artifact hash mismatch: declared {declared}, actual {actual}"
                )
            }
            Self::UnsupportedMediaType(media_type) => {
                write!(f, "no deterministic normalizer for media type {media_type}")
            }
            Self::InvalidUtf8 => f.write_str("text artifact is not valid UTF-8"),
            Self::InvalidJson(detail) => write!(f, "invalid JSON: {detail}"),
            Self::InvalidNdjson { line, detail } => {
                write!(f, "invalid NDJSON at line {line}: {detail}")
            }
        }
    }
}

impl std::error::Error for NormalizeError {}

pub fn normalize(raw: &RawArtifact) -> Result<NormalizedArtifact, NormalizeError> {
    let actual_input_hash = content_hash(&raw.bytes);
    if actual_input_hash != raw.content_hash {
        return Err(NormalizeError::InputHashMismatch {
            declared: raw.content_hash.clone(),
            actual: actual_input_hash,
        });
    }

    let (algorithm, bytes) = match raw.media_type.as_str() {
        "text/plain" | "text/markdown" | "text/csv" => (
            NormalizationAlgorithm::TextV1,
            normalize_text(&raw.bytes)?.into_bytes(),
        ),
        "application/json" => (
            NormalizationAlgorithm::JsonCanonicalV1,
            normalize_json(&raw.bytes)?.into_bytes(),
        ),
        "application/x-ndjson" => (
            NormalizationAlgorithm::NdjsonCanonicalV1,
            normalize_ndjson(&raw.bytes)?.into_bytes(),
        ),
        other => return Err(NormalizeError::UnsupportedMediaType(other.to_owned())),
    };

    let output_content_hash = content_hash(&bytes);
    Ok(NormalizedArtifact {
        tenant: raw.tenant.clone(),
        source_id: raw.source_id.clone(),
        virtual_uri: raw.virtual_uri.clone(),
        media_type: raw.media_type.clone(),
        bytes,
        manifest: NormalizationManifest {
            contract_version: NORMALIZATION_CONTRACT_VERSION,
            algorithm,
            input_content_hash: raw.content_hash.clone(),
            output_content_hash,
            media_type: raw.media_type.clone(),
        },
    })
}

fn normalize_text(bytes: &[u8]) -> Result<String, NormalizeError> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| NormalizeError::InvalidUtf8)?;
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            output.push('\n');
        } else {
            output.push(character);
        }
    }
    Ok(output)
}

fn normalize_json(bytes: &[u8]) -> Result<String, NormalizeError> {
    let text = normalize_text(bytes)?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| NormalizeError::InvalidJson(error.to_string()))?;
    let mut output = String::new();
    write_canonical_json(&value, &mut output);
    Ok(output)
}

fn normalize_ndjson(bytes: &[u8]) -> Result<String, NormalizeError> {
    let text = normalize_text(bytes)?;
    let mut normalized = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        if line.trim().is_empty() {
            normalized.push(String::new());
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| NormalizeError::InvalidNdjson {
                line: index + 1,
                detail: error.to_string(),
            })?;
        let mut canonical = String::new();
        write_canonical_json(&value, &mut canonical);
        normalized.push(canonical);
    }
    Ok(normalized.join("\n"))
}

/// Canonical JSON independent of serde_json's optional map-order implementation.
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

fn content_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
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

    fn raw(media_type: &str, bytes: &[u8]) -> RawArtifact {
        RawArtifact {
            tenant: TenantId("acme".into()),
            source_id: SourceId::from("source:test"),
            virtual_uri: "fs://dataset/test".into(),
            media_type: media_type.into(),
            content_hash: content_hash(bytes),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn bom_and_line_endings_have_one_text_representation() {
        let left = normalize(&raw("text/plain", b"\xef\xbb\xbfalpha\r\nbeta\r")).unwrap();
        let right = normalize(&raw("text/plain", b"alpha\nbeta\n")).unwrap();
        assert_eq!(left.bytes, b"alpha\nbeta\n");
        assert_eq!(left.bytes, right.bytes);
        assert_eq!(
            left.manifest.output_content_hash,
            right.manifest.output_content_hash
        );
        assert_ne!(
            left.manifest.input_content_hash,
            right.manifest.input_content_hash
        );
    }

    #[test]
    fn json_key_order_and_insignificant_whitespace_are_canonicalized() {
        let left = normalize(&raw("application/json", br#"{ "b": 2, "a": [3, 1] }"#)).unwrap();
        let right = normalize(&raw("application/json", br#"{"a":[3,1],"b":2}"#)).unwrap();
        assert_eq!(left.bytes, br#"{"a":[3,1],"b":2}"#);
        assert_eq!(left.bytes, right.bytes);
        assert_eq!(
            left.manifest.output_content_hash,
            right.manifest.output_content_hash
        );
    }

    #[test]
    fn ndjson_canonicalizes_records_without_reordering_lines() {
        let normalized = normalize(&raw(
            "application/x-ndjson",
            b"{\"b\":2,\"a\":1}\r\n\r\n{\"z\":0}\r\n",
        ))
        .unwrap();
        assert_eq!(normalized.bytes, b"{\"a\":1,\"b\":2}\n\n{\"z\":0}\n");
    }

    #[test]
    fn declared_raw_hash_is_verified_before_transform() {
        let mut artifact = raw("text/plain", b"trusted");
        artifact.bytes = b"tampered".to_vec();
        assert!(matches!(
            normalize(&artifact),
            Err(NormalizeError::InputHashMismatch { .. })
        ));
    }

    #[test]
    fn unsupported_media_type_fails_closed() {
        assert_eq!(
            normalize(&raw("application/octet-stream", b"x")),
            Err(NormalizeError::UnsupportedMediaType(
                "application/octet-stream".into()
            ))
        );
    }
}

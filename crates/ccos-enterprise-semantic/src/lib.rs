//! Deterministic semantic-web interoperability for the CCOS Enterprise Knowledge Plane.
//!
//! P4d exports validated CCOS schemas/proposals as standard RDF N-Triples, JSON-LD 1.1
//! node objects and a SHACL Core shapes-graph subset. It does not import arbitrary RDF,
//! execute SHACL engines, or infer OWL semantics. Canonical Knowledge and ontology
//! validation remain authoritative.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ccos_enterprise_extract::ExtractedValue;
use ccos_enterprise_ontology::{EntitySchema, Ontology, ValueType, Violation};
use ccos_enterprise_resolution::EntityProposal;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SEMANTIC_INTEROP_CONTRACT_VERSION: u32 = 1;

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_PROPERTY: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDFS_DOMAIN: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const RDFS_LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const SH_NODE_SHAPE: &str = "http://www.w3.org/ns/shacl#NodeShape";
const SH_PROPERTY_SHAPE: &str = "http://www.w3.org/ns/shacl#PropertyShape";
const SH_TARGET_CLASS: &str = "http://www.w3.org/ns/shacl#targetClass";
const SH_PROPERTY: &str = "http://www.w3.org/ns/shacl#property";
const SH_PATH: &str = "http://www.w3.org/ns/shacl#path";
const SH_DATATYPE: &str = "http://www.w3.org/ns/shacl#datatype";
const SH_MIN_COUNT: &str = "http://www.w3.org/ns/shacl#minCount";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticNamespace {
    base: String,
}

impl SemanticNamespace {
    pub fn new(base: impl Into<String>) -> Result<Self, SemanticError> {
        let base = base.into();
        if !is_safe_absolute_iri(&base) || !(base.ends_with('/') || base.ends_with('#')) {
            return Err(SemanticError::InvalidBaseIri(base));
        }
        Ok(Self { base })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn class_iri(&self, entity_type: &str) -> String {
        format!("{}class/{}", self.base, encode_segment(entity_type))
    }

    fn property_iri(&self, property: &str) -> String {
        format!("{}property/{}", self.base, encode_segment(property))
    }

    fn entity_iri(&self, tenant: &str, entity_id: &str) -> String {
        format!(
            "{}entity/{}/{}",
            self.base,
            encode_segment(tenant),
            encode_segment(entity_id)
        )
    }

    fn shape_iri(&self, entity_type: &str) -> String {
        format!("{}shape/{}", self.base, encode_segment(entity_type))
    }

    fn null_datatype_iri(&self) -> String {
        format!("{}datatype/null", self.base)
    }

    fn json_datatype_iri(&self) -> String {
        format!("{}datatype/json", self.base)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RdfTerm {
    Iri(String),
    BlankNode(String),
    Literal {
        lexical: String,
        datatype: Option<String>,
    },
}

impl RdfTerm {
    fn iri(value: impl Into<String>) -> Self {
        Self::Iri(value.into())
    }

    fn literal(lexical: impl Into<String>, datatype: impl Into<String>) -> Self {
        Self::Literal {
            lexical: lexical.into(),
            datatype: Some(datatype.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RdfTriple {
    pub subject: RdfTerm,
    pub predicate: String,
    pub object: RdfTerm,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RdfDocument {
    triples: BTreeSet<RdfTriple>,
}

impl RdfDocument {
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    pub fn triples(&self) -> impl Iterator<Item = &RdfTriple> {
        self.triples.iter()
    }

    pub fn to_ntriples(&self) -> String {
        let mut output = String::new();
        for triple in &self.triples {
            write_term(&triple.subject, &mut output);
            output.push(' ');
            write_iri(&triple.predicate, &mut output);
            output.push(' ');
            write_term(&triple.object, &mut output);
            output.push_str(" .\n");
        }
        output
    }

    fn insert(&mut self, subject: RdfTerm, predicate: &str, object: RdfTerm) {
        self.triples.insert(RdfTriple {
            subject,
            predicate: predicate.to_owned(),
            object,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonLdDocument {
    canonical: String,
}

impl JsonLdDocument {
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticError {
    InvalidBaseIri(String),
    UnknownEntityType(String),
    SchemaViolations(Vec<Violation>),
    InvalidNumber(String),
    InvalidJson(String),
    JsonSerialization(String),
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseIri(value) => write!(f, "invalid semantic base IRI {value:?}"),
            Self::UnknownEntityType(value) => write!(f, "unknown ontology entity type {value:?}"),
            Self::SchemaViolations(violations) => {
                write!(f, "proposal is invalid under ontology: {violations:?}")
            }
            Self::InvalidNumber(value) => write!(f, "invalid numeric lexical form {value:?}"),
            Self::InvalidJson(detail) => write!(f, "invalid JSON literal: {detail}"),
            Self::JsonSerialization(detail) => write!(f, "JSON-LD serialization failed: {detail}"),
        }
    }
}

impl std::error::Error for SemanticError {}

/// Project one ontology entity schema as an RDF/RDFS graph.
pub fn ontology_schema_rdf(
    ontology: &Ontology,
    entity_type: &str,
    namespace: &SemanticNamespace,
) -> Result<RdfDocument, SemanticError> {
    let schema = ontology
        .entity_schema(entity_type)
        .ok_or_else(|| SemanticError::UnknownEntityType(entity_type.to_owned()))?;
    let class = RdfTerm::iri(namespace.class_iri(entity_type));
    let mut document = RdfDocument::default();
    document.insert(class.clone(), RDF_TYPE, RdfTerm::iri(RDFS_CLASS));

    for property in schema.properties.values() {
        let property_iri = RdfTerm::iri(namespace.property_iri(&property.name));
        document.insert(property_iri.clone(), RDF_TYPE, RdfTerm::iri(RDF_PROPERTY));
        document.insert(property_iri.clone(), RDFS_DOMAIN, class.clone());
        document.insert(
            property_iri,
            RDFS_RANGE,
            RdfTerm::iri(datatype_iri(property.value_type, namespace)),
        );
    }
    Ok(document)
}

/// Project the CCOS ontology constraints that have direct SHACL Core equivalents.
///
/// P4d emits `sh:NodeShape`, `sh:targetClass`, `sh:property`, `sh:path`, `sh:datatype`
/// and `sh:minCount 1` for required properties. CCOS `allow_extra_properties=false` is not
/// represented as `sh:closed` in this slice because doing so correctly requires an ignored
/// property list for RDF metadata such as `rdf:type`.
pub fn ontology_schema_shacl(
    ontology: &Ontology,
    entity_type: &str,
    namespace: &SemanticNamespace,
) -> Result<RdfDocument, SemanticError> {
    let schema = ontology
        .entity_schema(entity_type)
        .ok_or_else(|| SemanticError::UnknownEntityType(entity_type.to_owned()))?;
    shacl_document(schema, namespace)
}

fn shacl_document(
    schema: &EntitySchema,
    namespace: &SemanticNamespace,
) -> Result<RdfDocument, SemanticError> {
    let mut document = RdfDocument::default();
    let node_shape = RdfTerm::iri(namespace.shape_iri(&schema.entity_type));
    let class = RdfTerm::iri(namespace.class_iri(&schema.entity_type));
    document.insert(node_shape.clone(), RDF_TYPE, RdfTerm::iri(SH_NODE_SHAPE));
    document.insert(node_shape.clone(), SH_TARGET_CLASS, class);

    for property in schema.properties.values() {
        let blank_id = property_shape_blank_id(&schema.entity_type, &property.name);
        let property_shape = RdfTerm::BlankNode(blank_id);
        document.insert(node_shape.clone(), SH_PROPERTY, property_shape.clone());
        document.insert(
            property_shape.clone(),
            RDF_TYPE,
            RdfTerm::iri(SH_PROPERTY_SHAPE),
        );
        document.insert(
            property_shape.clone(),
            SH_PATH,
            RdfTerm::iri(namespace.property_iri(&property.name)),
        );
        document.insert(
            property_shape.clone(),
            SH_DATATYPE,
            RdfTerm::iri(datatype_iri(property.value_type, namespace)),
        );
        if property.required {
            document.insert(
                property_shape,
                SH_MIN_COUNT,
                RdfTerm::literal("1", XSD_INTEGER),
            );
        }
    }
    Ok(document)
}

/// Export a validated proposal as a tenant-scoped RDF graph.
pub fn proposal_rdf(
    ontology: &Ontology,
    proposal: &EntityProposal,
    namespace: &SemanticNamespace,
) -> Result<RdfDocument, SemanticError> {
    validate(ontology, proposal)?;
    let subject = RdfTerm::iri(namespace.entity_iri(&proposal.tenant.0, proposal.id.as_str()));
    let mut document = RdfDocument::default();
    document.insert(
        subject.clone(),
        RDF_TYPE,
        RdfTerm::iri(namespace.class_iri(&proposal.entity_type)),
    );
    if let Some(label) = proposal.labels.iter().next() {
        document.insert(
            subject.clone(),
            RDFS_LABEL,
            RdfTerm::literal(label.clone(), XSD_STRING),
        );
    }
    for fact in &proposal.facts {
        document.insert(
            subject.clone(),
            &namespace.property_iri(&fact.predicate),
            extracted_value_rdf(&fact.value, namespace)?,
        );
    }
    Ok(document)
}

/// Export a validated proposal as one deterministic JSON-LD 1.1 node object.
pub fn proposal_json_ld(
    ontology: &Ontology,
    proposal: &EntityProposal,
    namespace: &SemanticNamespace,
) -> Result<JsonLdDocument, SemanticError> {
    validate(ontology, proposal)?;

    let mut root = BTreeMap::<String, Value>::new();
    let mut context = BTreeMap::<String, Value>::new();
    context.insert("@version".to_owned(), Value::from(1.1));
    context.insert(
        "ccos".to_owned(),
        Value::String(namespace.base().to_owned()),
    );
    root.insert(
        "@context".to_owned(),
        serde_json::to_value(context)
            .map_err(|error| SemanticError::JsonSerialization(error.to_string()))?,
    );
    root.insert(
        "@id".to_owned(),
        Value::String(namespace.entity_iri(&proposal.tenant.0, proposal.id.as_str())),
    );
    root.insert(
        "@type".to_owned(),
        Value::String(namespace.class_iri(&proposal.entity_type)),
    );

    if let Some(label) = proposal.labels.iter().next() {
        root.insert(
            RDFS_LABEL.to_owned(),
            Value::Array(vec![value_object(Value::String(label.clone()), None)]),
        );
    }

    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for fact in &proposal.facts {
        grouped
            .entry(namespace.property_iri(&fact.predicate))
            .or_default()
            .push(extracted_value_json_ld(&fact.value, namespace)?);
    }
    for (property, mut values) in grouped {
        values.sort_by_key(canonical_json_value);
        root.insert(property, Value::Array(values));
    }

    let value = serde_json::to_value(root)
        .map_err(|error| SemanticError::JsonSerialization(error.to_string()))?;
    Ok(JsonLdDocument {
        canonical: canonical_json_value(&value),
    })
}

fn validate(ontology: &Ontology, proposal: &EntityProposal) -> Result<(), SemanticError> {
    let report = ontology.validate_proposal(proposal);
    if report.is_valid() {
        Ok(())
    } else {
        Err(SemanticError::SchemaViolations(report.violations))
    }
}

fn extracted_value_rdf(
    value: &ExtractedValue,
    namespace: &SemanticNamespace,
) -> Result<RdfTerm, SemanticError> {
    match value {
        ExtractedValue::Null => Ok(RdfTerm::literal("null", namespace.null_datatype_iri())),
        ExtractedValue::Bool(value) => Ok(RdfTerm::literal(
            if *value { "true" } else { "false" },
            XSD_BOOLEAN,
        )),
        ExtractedValue::Number(value) => {
            validate_number(value)?;
            Ok(RdfTerm::literal(value.clone(), XSD_DOUBLE))
        }
        ExtractedValue::String(value) => Ok(RdfTerm::literal(value.clone(), XSD_STRING)),
        ExtractedValue::Json(value) => {
            let parsed: Value = serde_json::from_str(value)
                .map_err(|error| SemanticError::InvalidJson(error.to_string()))?;
            Ok(RdfTerm::literal(
                canonical_json_value(&parsed),
                namespace.json_datatype_iri(),
            ))
        }
    }
}

fn extracted_value_json_ld(
    value: &ExtractedValue,
    namespace: &SemanticNamespace,
) -> Result<Value, SemanticError> {
    match value {
        ExtractedValue::Null => Ok(value_object(
            Value::String("null".into()),
            Some(namespace.null_datatype_iri()),
        )),
        ExtractedValue::Bool(value) => Ok(value_object(Value::Bool(*value), None)),
        ExtractedValue::Number(value) => {
            let parsed = validate_number(value)?;
            Ok(value_object(parsed, None))
        }
        ExtractedValue::String(value) => Ok(value_object(Value::String(value.clone()), None)),
        ExtractedValue::Json(value) => {
            let parsed: Value = serde_json::from_str(value)
                .map_err(|error| SemanticError::InvalidJson(error.to_string()))?;
            let mut object = BTreeMap::<String, Value>::new();
            object.insert("@type".into(), Value::String("@json".into()));
            object.insert("@value".into(), parsed);
            serde_json::to_value(object)
                .map_err(|error| SemanticError::JsonSerialization(error.to_string()))
        }
    }
}

fn value_object(value: Value, datatype: Option<String>) -> Value {
    let mut object = BTreeMap::<String, Value>::new();
    if let Some(datatype) = datatype {
        object.insert("@type".into(), Value::String(datatype));
    }
    object.insert("@value".into(), value);
    serde_json::to_value(object).expect("BTreeMap<String, Value> serialization is infallible")
}

fn validate_number(value: &str) -> Result<Value, SemanticError> {
    let parsed: Value =
        serde_json::from_str(value).map_err(|_| SemanticError::InvalidNumber(value.to_owned()))?;
    if parsed.is_number() {
        Ok(parsed)
    } else {
        Err(SemanticError::InvalidNumber(value.to_owned()))
    }
}

fn datatype_iri(value_type: ValueType, namespace: &SemanticNamespace) -> String {
    match value_type {
        ValueType::Null => namespace.null_datatype_iri(),
        ValueType::Bool => XSD_BOOLEAN.to_owned(),
        ValueType::Number => XSD_DOUBLE.to_owned(),
        ValueType::String => XSD_STRING.to_owned(),
        ValueType::Json => namespace.json_datatype_iri(),
    }
}

fn property_shape_blank_id(entity_type: &str, property: &str) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, entity_type.as_bytes());
    hash_part(&mut hasher, property.as_bytes());
    format!("ps{}", &hex_lower(&hasher.finalize())[..24])
}

fn is_safe_absolute_iri(value: &str) -> bool {
    if value.is_empty() || !value.contains(':') {
        return false;
    }
    value.chars().all(|character| {
        !character.is_control()
            && !character.is_whitespace()
            && !matches!(
                character,
                '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\'
            )
    })
}

fn encode_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte as char);
        } else {
            output.push('%');
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 0x0f));
        }
    }
    output
}

fn hex_digit(value: u8) -> char {
    b"0123456789ABCDEF"[value as usize] as char
}

fn write_term(term: &RdfTerm, output: &mut String) {
    match term {
        RdfTerm::Iri(value) => write_iri(value, output),
        RdfTerm::BlankNode(value) => {
            output.push_str("_:");
            output.push_str(value);
        }
        RdfTerm::Literal { lexical, datatype } => {
            output.push('"');
            write_literal(lexical, output);
            output.push('"');
            if let Some(datatype) = datatype {
                output.push_str("^^");
                write_iri(datatype, output);
            }
        }
    }
}

fn write_iri(value: &str, output: &mut String) {
    output.push('<');
    output.push_str(value);
    output.push('>');
}

fn write_literal(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04X}", character as u32);
            }
            character => output.push(character),
        }
    }
}

fn canonical_json_value(value: &Value) -> String {
    let mut output = String::new();
    write_canonical_json(value, &mut output);
    output
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value).expect("serializing a JSON string cannot fail"),
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
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

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
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
    use ccos_enterprise_extract::CandidateId;
    use ccos_enterprise_knowledge_model::{EntityId, EvidenceId, TenantId};
    use ccos_enterprise_ontology::{PropertySpec, ValueType};
    use ccos_enterprise_resolution::FactProposal;

    fn ontology() -> Ontology {
        Ontology::new(
            TenantId("tenant-a".into()),
            "v1",
            [EntitySchema::new(
                "company",
                [
                    PropertySpec::new("id", ValueType::String, true).unwrap(),
                    PropertySpec::new("active", ValueType::Bool, false).unwrap(),
                    PropertySpec::new("metadata", ValueType::Json, false).unwrap(),
                ],
                false,
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn proposal(reverse: bool) -> EntityProposal {
        let candidate = CandidateId("candidate:1".into());
        let evidence = EvidenceId::from("evidence:1");
        let mut facts = vec![
            FactProposal {
                candidate: candidate.clone(),
                predicate: "id".into(),
                value: ExtractedValue::String("C-7".into()),
                evidence: evidence.clone(),
            },
            FactProposal {
                candidate: candidate.clone(),
                predicate: "active".into(),
                value: ExtractedValue::Bool(true),
                evidence: evidence.clone(),
            },
            FactProposal {
                candidate: candidate.clone(),
                predicate: "metadata".into(),
                value: ExtractedValue::Json("{\"z\":1,\"a\":2}".into()),
                evidence: evidence.clone(),
            },
        ];
        if reverse {
            facts.reverse();
        }
        EntityProposal {
            id: EntityId::new("company/7"),
            tenant: TenantId("tenant-a".into()),
            entity_type: "company".into(),
            candidates: BTreeSet::from([candidate]),
            evidence: BTreeSet::from([evidence]),
            labels: BTreeSet::from(["Acme".into()]),
            facts,
        }
    }

    #[test]
    fn shacl_projection_uses_core_constraints() {
        let namespace = SemanticNamespace::new("https://example.test/ccos/").unwrap();
        let output = ontology_schema_shacl(&ontology(), "company", &namespace)
            .unwrap()
            .to_ntriples();
        assert!(output.contains(SH_NODE_SHAPE));
        assert!(output.contains(SH_TARGET_CLASS));
        assert!(output.contains(SH_MIN_COUNT));
        assert!(output.contains(XSD_STRING));
    }

    #[test]
    fn json_ld_is_deterministic_for_fact_order_and_uses_json_literal() {
        let namespace = SemanticNamespace::new("https://example.test/ccos/").unwrap();
        let left = proposal_json_ld(&ontology(), &proposal(false), &namespace).unwrap();
        let right = proposal_json_ld(&ontology(), &proposal(true), &namespace).unwrap();
        assert_eq!(left, right);
        assert!(left.as_str().contains("\"@version\":1.1"));
        assert!(left.as_str().contains("\"@type\":\"@json\""));
        assert!(left.as_str().contains("\"@value\":true"));
    }

    #[test]
    fn rdf_projection_is_sorted_and_tenant_scoped() {
        let namespace = SemanticNamespace::new("urn:ccos:test/").unwrap();
        let document = proposal_rdf(&ontology(), &proposal(false), &namespace).unwrap();
        let first = document.to_ntriples();
        let second = document.to_ntriples();
        assert_eq!(first, second);
        assert!(first.contains("entity/tenant-a/company%2F7"));
        assert!(first.contains(XSD_BOOLEAN));
    }

    #[test]
    fn invalid_proposal_never_exports() {
        let namespace = SemanticNamespace::new("https://example.test/ccos/").unwrap();
        let mut proposal = proposal(false);
        proposal.tenant = TenantId("tenant-b".into());
        assert!(matches!(
            proposal_rdf(&ontology(), &proposal, &namespace),
            Err(SemanticError::SchemaViolations(_))
        ));
    }
}

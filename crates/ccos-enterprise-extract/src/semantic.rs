//! Opt-in, conservative English/French relation candidates. This is a versioned
//! rule baseline with abstention, not a general language model or a truth gate.
use crate::{evidence_id, CandidateId};
use ccos_enterprise_ingest::RawArtifact;
use ccos_enterprise_knowledge_model::{AssertionKind, EvidenceRecord, SourceId, TenantId};
use ccos_enterprise_parse::{parse, ByteSpan};
use sha2::{Digest, Sha256};

pub const SEMANTIC_RULE_VERSION: &str = "ccos-relations-en-fr-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKind {
    WorksFor,
    LocatedIn,
    DependsOn,
}
impl RelationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorksFor => "works_for",
            Self::LocatedIn => "located_in",
            Self::DependsOn => "depends_on",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    Affirmed,
    Negated,
}
impl Polarity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Affirmed => "affirmed",
            Self::Negated => "negated",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mention {
    text: String,
    span: ByteSpan,
}
impl Mention {
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn span(&self) -> ByteSpan {
        self.span
    }
}

/// No canonical entity IDs, knowledge mutation, trust score or promotion API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationCandidate {
    id: CandidateId,
    tenant: TenantId,
    source: SourceId,
    subject: Mention,
    object: Mention,
    relation: RelationKind,
    polarity: Polarity,
    evidence: EvidenceRecord,
}
impl RelationCandidate {
    pub fn id(&self) -> &CandidateId {
        &self.id
    }
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub fn source(&self) -> &SourceId {
        &self.source
    }
    pub fn subject(&self) -> &Mention {
        &self.subject
    }
    pub fn object(&self) -> &Mention {
        &self.object
    }
    pub const fn relation(&self) -> RelationKind {
        self.relation
    }
    pub const fn polarity(&self) -> Polarity {
        self.polarity
    }
    pub const fn kind(&self) -> AssertionKind {
        AssertionKind::Observation
    }
    pub fn evidence(&self) -> &EvidenceRecord {
        &self.evidence
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstentionReason {
    UnsupportedGrammar,
    AmbiguousMentions,
    UnitTooLarge,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abstention {
    pub unit_ordinal: usize,
    pub span: ByteSpan,
    pub reason: AbstentionReason,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticBatch {
    pub candidates: Vec<RelationCandidate>,
    pub abstentions: Vec<Abstention>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticError {
    Limit,
    UnsupportedMedia,
    InvalidSource(String),
}
impl std::fmt::Display for SemanticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "semantic extraction {self:?}")
    }
}
impl std::error::Error for SemanticError {}

/// Maximum 4 MiB input, 8,192 units, 4,096 candidates. Large individual units
/// abstain. Parsing validates the declared whole-source hash before extraction.
pub fn extract_relations(raw: &RawArtifact) -> Result<SemanticBatch, SemanticError> {
    if raw.bytes.len() > 4 * 1024 * 1024 {
        return Err(SemanticError::Limit);
    }
    if !matches!(raw.media_type.as_str(), "text/plain" | "text/markdown") {
        return Err(SemanticError::UnsupportedMedia);
    }
    let parsed = parse(raw).map_err(|e| SemanticError::InvalidSource(e.to_string()))?;
    if parsed.units.len() > 8192 {
        return Err(SemanticError::Limit);
    }
    let mut batch = SemanticBatch {
        candidates: Vec::new(),
        abstentions: Vec::new(),
    };
    for unit in parsed.units {
        let original = std::str::from_utf8(&raw.bytes[unit.raw_span.start..unit.raw_span.end])
            .map_err(|_| SemanticError::InvalidSource("UTF-8".into()))?;
        if original.trim().is_empty() {
            continue;
        }
        let outcome = if original.len() > 2048 {
            Err(AbstentionReason::UnitTooLarge)
        } else {
            parse_relation(original, unit.raw_span.start)
        };
        match outcome {
            Err(reason) => batch.abstentions.push(Abstention {
                unit_ordinal: unit.ordinal,
                span: unit.raw_span,
                reason,
            }),
            Ok((subject, relation, polarity, object)) => {
                if batch.candidates.len() >= 4096 {
                    return Err(SemanticError::Limit);
                }
                let locator = unit.evidence_locator();
                let evidence = EvidenceRecord {
                    id: evidence_id(raw, &locator),
                    tenant: raw.tenant.clone(),
                    source: raw.source_id.clone(),
                    locator: Some(locator),
                    content_hash: Some(raw.content_hash.clone()),
                };
                let identity = serde_json::json!([
                    SEMANTIC_RULE_VERSION,
                    raw.tenant.as_str(),
                    raw.source_id.as_str(),
                    raw.content_hash,
                    unit.raw_span.start,
                    unit.raw_span.end,
                    relation.as_str(),
                    polarity.as_str(),
                    subject.text(),
                    object.text()
                ]);
                let id = CandidateId(format!(
                    "candidate:relation:{:x}",
                    Sha256::digest(identity.to_string().as_bytes())
                ));
                batch.candidates.push(RelationCandidate {
                    id,
                    tenant: raw.tenant.clone(),
                    source: raw.source_id.clone(),
                    subject,
                    object,
                    relation,
                    polarity,
                    evidence,
                });
            }
        }
    }
    Ok(batch)
}

fn parse_relation(
    original: &str,
    offset: usize,
) -> Result<(Mention, RelationKind, Polarity, Mention), AbstentionReason> {
    use Polarity::*;
    use RelationKind::*;
    const RULES: &[(&str, RelationKind, Polarity)] = &[
        (" works at ", WorksFor, Affirmed),
        (" works for ", WorksFor, Affirmed),
        (" does not work at ", WorksFor, Negated),
        (" does not work for ", WorksFor, Negated),
        (" travaille chez ", WorksFor, Affirmed),
        (" ne travaille pas chez ", WorksFor, Negated),
        (" is located in ", LocatedIn, Affirmed),
        (" is not located in ", LocatedIn, Negated),
        (" est situé à ", LocatedIn, Affirmed),
        (" est située à ", LocatedIn, Affirmed),
        (" n'est pas situé à ", LocatedIn, Negated),
        (" n'est pas située à ", LocatedIn, Negated),
        (" depends on ", DependsOn, Affirmed),
        (" does not depend on ", DependsOn, Negated),
        (" dépend de ", DependsOn, Affirmed),
        (" ne dépend pas de ", DependsOn, Negated),
    ];
    let text = original.trim();
    let start = offset + original.len() - original.trim_start().len();
    let text = text.strip_suffix('.').unwrap_or(text);
    let mut found = None;
    for &(phrase, relation, polarity) in RULES {
        for (position, _) in text.match_indices(phrase) {
            if found.is_some() {
                return Err(AbstentionReason::UnsupportedGrammar);
            }
            found = Some((position, phrase.len(), relation, polarity));
        }
    }
    let (at, length, relation, polarity) = found.ok_or(AbstentionReason::UnsupportedGrammar)?;
    let left = &text[..at];
    let right = &text[at + length..];
    if !mention(left) || !mention(right) {
        return Err(AbstentionReason::AmbiguousMentions);
    }
    Ok((
        Mention {
            text: left.into(),
            span: ByteSpan {
                start,
                end: start + left.len(),
            },
        },
        relation,
        polarity,
        Mention {
            text: right.into(),
            span: ByteSpan {
                start: start + at + length,
                end: start + text.len(),
            },
        },
    ))
}
fn mention(s: &str) -> bool {
    const PRONOUNS: &[&str] = &[
        "I",
        "He",
        "She",
        "It",
        "We",
        "You",
        "They",
        "This",
        "That",
        "Il",
        "Elle",
        "Ils",
        "Elles",
        "Je",
        "Tu",
        "Nous",
        "Vous",
        "On",
        "Cela",
        "If",
        "Unless",
        "When",
        "Maybe",
        "Perhaps",
        "Not",
        "No",
        "Never",
        "According",
        "Si",
        "Quand",
        "Selon",
        "Pas",
        "Non",
        "Jamais",
        "Peut-être",
        "Peut-Être",
    ];
    if s.is_empty() || s.len() > 128 || s.trim() != s || PRONOUNS.contains(&s) {
        return false;
    }
    let words: Vec<_> = s.split(' ').collect();
    !words.is_empty()
        && words.len() <= 8
        && words.into_iter().all(|w| {
            !PRONOUNS.contains(&w)
                && w.chars().next().is_some_and(char::is_uppercase)
                && w.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '-' | '\'' | '’'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(text: &str) -> RawArtifact {
        RawArtifact {
            tenant: TenantId::new("acme").unwrap(),
            source_id: SourceId::new("s"),
            virtual_uri: "source://test".into(),
            media_type: "text/plain".into(),
            content_hash: format!("sha256:{:x}", Sha256::digest(text.as_bytes())),
            bytes: text.as_bytes().to_vec(),
        }
    }
    #[test]
    fn negation_unicode_raw_offsets_and_observation_identity_are_preserved() {
        let input =
            raw("\u{feff}  Élodie ne travaille pas chez Acme.\r\nAPI depends on Database.\r\n");
        let batch = extract_relations(&input).unwrap();
        assert_eq!(batch.candidates.len(), 2);
        assert!(batch.abstentions.is_empty());
        let c = &batch.candidates[0];
        assert_eq!(c.polarity(), Polarity::Negated);
        assert_eq!(c.kind(), AssertionKind::Observation);
        assert_eq!(c.subject().text(), "Élodie");
        for c in &batch.candidates {
            for m in [c.subject(), c.object()] {
                assert_eq!(
                    &input.bytes[m.span().start..m.span().end],
                    m.text().as_bytes()
                )
            }
            assert_eq!(
                c.evidence().content_hash.as_ref(),
                Some(&input.content_hash)
            );
        }
        assert_eq!(extract_relations(&input).unwrap(), batch);
        let mut another = input.clone();
        another.tenant = TenantId::new("other").unwrap();
        assert_ne!(
            extract_relations(&another).unwrap().candidates[0].id(),
            c.id()
        );
        another = input;
        another.bytes[5] ^= 1;
        assert!(extract_relations(&another).is_err());
    }
    #[test]
    fn uncertainty_pronouns_questions_attribution_and_coordination_abstain() {
        for sentence in [
            "Alice might work at Acme.",
            "She works at Acme.",
            "Alice works at Acme?",
            "Bob says Alice works at Acme.",
            "Alice works at Acme and Beta.",
            "If Alice works at Acme.",
            "Alice works at Acme since Monday.",
            "Alice works at Acme; Bob works at Beta.",
        ] {
            let result = extract_relations(&raw(sentence)).unwrap();
            assert!(result.candidates.is_empty(), "{sentence}");
            assert_eq!(result.abstentions.len(), 1);
        }
    }
    #[test]
    fn source_and_output_limits_fail_closed() {
        assert_eq!(
            extract_relations(&raw(&"a".repeat(4 * 1024 * 1024 + 1))),
            Err(SemanticError::Limit)
        );
        assert_eq!(
            extract_relations(&raw(&"API depends on Database.\n".repeat(4097))),
            Err(SemanticError::Limit)
        );
        assert_eq!(
            extract_relations(&raw(&"unknown\n".repeat(8193))),
            Err(SemanticError::Limit)
        );
        let batch = extract_relations(&raw(&"A".repeat(2049))).unwrap();
        assert_eq!(batch.abstentions[0].reason, AbstentionReason::UnitTooLarge);
    }
}

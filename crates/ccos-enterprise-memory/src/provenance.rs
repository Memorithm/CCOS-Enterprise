//! Exact evidence/source joins and bounded byte citations. This proves a declared
//! provenance link and content integrity, not semantic entailment or truth.
use crate::{
    GovernedMemoryContextAssembly, GovernedMemoryProjection, MemoryAssetId, MemoryEvidenceRef,
};
use ccos_enterprise_knowledge_model::{EvidenceId, EvidenceRecord, SourceId, SourceRecord};
use ccos_enterprise_tenancy::TenantId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    TenantMismatch,
    ProjectionMismatch,
    MissingEvidence,
    MissingSource,
    InvalidRecord,
    MissingHash,
    InvalidHash,
    ContentMismatch,
    InvalidSpan,
    SourceUnavailable,
    Limit,
}
impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "memory provenance {:?}", self)
    }
}
impl std::error::Error for ProvenanceError {}

/// The caller owns the source service; record locators never trigger network or
/// filesystem access by themselves. Implementations must enforce tenant access.
pub trait SourceBytes {
    fn open(
        &self,
        tenant: &TenantId,
        source: &SourceRecord,
    ) -> Result<Box<dyn Read>, ProvenanceError>;
}

/// Immutable metadata copied from acknowledged, tenant-scoped knowledge state.
pub struct EvidenceCatalog {
    tenant: TenantId,
    evidence: BTreeMap<EvidenceId, EvidenceRecord>,
    sources: BTreeMap<SourceId, SourceRecord>,
}
impl EvidenceCatalog {
    pub fn new(
        tenant: TenantId,
        sources: impl IntoIterator<Item = SourceRecord>,
        evidence: impl IntoIterator<Item = EvidenceRecord>,
    ) -> Result<Self, ProvenanceError> {
        if TenantId::validated(tenant.as_str()).as_ref() != Some(&tenant) {
            return Err(ProvenanceError::TenantMismatch);
        }
        let mut catalog = Self {
            tenant,
            sources: BTreeMap::new(),
            evidence: BTreeMap::new(),
        };
        for source in sources {
            if source.tenant != catalog.tenant {
                return Err(ProvenanceError::TenantMismatch);
            }
            if !valid_id(source.id.as_str())
                || source.locator.is_empty()
                || source.locator.len() > 8192
            {
                return Err(ProvenanceError::InvalidRecord);
            }
            if catalog.sources.insert(source.id.clone(), source).is_some() {
                return Err(ProvenanceError::InvalidRecord);
            }
        }
        for record in evidence {
            if record.tenant != catalog.tenant {
                return Err(ProvenanceError::TenantMismatch);
            }
            if !valid_id(record.id.as_str()) || !catalog.sources.contains_key(&record.source) {
                return Err(ProvenanceError::InvalidRecord);
            }
            if catalog.evidence.insert(record.id.clone(), record).is_some() {
                return Err(ProvenanceError::InvalidRecord);
            }
        }
        Ok(catalog)
    }
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

/// Limits apply to the entire resolved context, including repeated quote bytes.
#[derive(Debug, Clone, Copy)]
pub struct CitationBudget {
    pub max_sources: usize,
    pub max_source_bytes: usize,
    pub max_total_source_bytes: usize,
    pub max_citations: usize,
    pub max_quote_bytes: usize,
    pub max_lineage_visits: usize,
}
impl CitationBudget {
    pub fn bounded(max_quote_bytes: usize) -> Self {
        Self {
            max_sources: 64,
            max_source_bytes: 16 * 1024 * 1024,
            max_total_source_bytes: 64 * 1024 * 1024,
            max_citations: 1024,
            max_quote_bytes,
            max_lineage_visits: 4096,
        }
    }
    fn validate(self) -> Result<Self, ProvenanceError> {
        let maximum = Self::bounded(16 * 1024 * 1024);
        if self.max_sources > maximum.max_sources
            || self.max_source_bytes > maximum.max_source_bytes
            || self.max_total_source_bytes > maximum.max_total_source_bytes
            || self.max_citations > maximum.max_citations
            || self.max_quote_bytes > maximum.max_quote_bytes
            || self.max_lineage_visits > maximum.max_lineage_visits
        {
            return Err(ProvenanceError::Limit);
        }
        Ok(self)
    }
}

/// Constructible only by successful hash and span verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCitation {
    reference: MemoryEvidenceRef,
    evidence: EvidenceId,
    source: SourceId,
    source_locator: String,
    content_hash: String,
    start: usize,
    end: usize,
    quote: Vec<u8>,
    quote_hash: String,
}
impl VerifiedCitation {
    pub fn reference(&self) -> &MemoryEvidenceRef {
        &self.reference
    }
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence
    }
    pub fn source_id(&self) -> &SourceId {
        &self.source
    }
    pub fn source_locator(&self) -> &str {
        &self.source_locator
    }
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
    pub fn span(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }
    pub fn quote_bytes(&self) -> &[u8] {
        &self.quote
    }
    pub fn quote_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.quote).ok()
    }
    pub fn quote_hash(&self) -> &str {
        &self.quote_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedMemoryAsset {
    asset_id: MemoryAssetId,
    payload_sha256: String,
    citations: Vec<VerifiedCitation>,
}
impl CitedMemoryAsset {
    pub fn asset_id(&self) -> &MemoryAssetId {
        &self.asset_id
    }
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }
    pub fn citations(&self) -> &[VerifiedCitation] {
        &self.citations
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedMemoryContext {
    tenant: TenantId,
    projection_sha256: String,
    items: Vec<CitedMemoryAsset>,
    quote_bytes: usize,
}
impl CitedMemoryContext {
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub fn projection_sha256(&self) -> &str {
        &self.projection_sha256
    }
    pub fn items(&self) -> &[CitedMemoryAsset] {
        &self.items
    }
    pub fn quote_bytes(&self) -> usize {
        self.quote_bytes
    }
}

/// Resolve every direct and inherited reference from an already admitted context.
/// There is no partial success: one missing/mismatched source rejects the result.
pub fn cite_governed_context(
    assembly: &GovernedMemoryContextAssembly,
    projection: &GovernedMemoryProjection,
    catalog: &EvidenceCatalog,
    source_bytes: &impl SourceBytes,
    budget: CitationBudget,
) -> Result<CitedMemoryContext, ProvenanceError> {
    let budget = budget.validate()?;
    if assembly.tenant() != catalog.tenant() || assembly.tenant() != &projection.tenant {
        return Err(ProvenanceError::TenantMismatch);
    }
    if crate::governed_recall::projection_fingerprint(projection)
        .map_err(|_| ProvenanceError::ProjectionMismatch)?
        != *assembly.projection_sha256()
    {
        return Err(ProvenanceError::ProjectionMismatch);
    }
    let mut resolver = Resolver {
        catalog,
        source_bytes,
        budget,
        cache: BTreeMap::new(),
        source_total: 0,
        quote_total: 0,
        citation_total: 0,
    };
    let mut items = Vec::new();
    let mut visits = 0usize;
    for chunk in assembly.chunks() {
        let mut refs = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut pending = vec![chunk.asset_id.clone()];
        while let Some(asset) = pending.pop() {
            if !seen.insert(asset.clone()) {
                continue;
            }
            visits = visits.checked_add(1).ok_or(ProvenanceError::Limit)?;
            if visits > budget.max_lineage_visits {
                return Err(ProvenanceError::Limit);
            }
            let descriptor = projection
                .graph
                .descriptor(&asset)
                .ok_or(ProvenanceError::ProjectionMismatch)?;
            for reference in descriptor.lineage.evidence() {
                refs.insert(reference.clone());
                if refs.len() > budget.max_citations {
                    return Err(ProvenanceError::Limit);
                }
            }
            for parent in descriptor.lineage.parents() {
                if pending.len() + seen.len() >= budget.max_lineage_visits {
                    return Err(ProvenanceError::Limit);
                }
                if !seen.contains(parent) {
                    pending.push(parent.clone());
                }
            }
        }
        if refs.is_empty() {
            return Err(ProvenanceError::MissingEvidence);
        }
        let citations = refs
            .iter()
            .map(|r| resolver.resolve(r))
            .collect::<Result<Vec<_>, _>>()?;
        items.push(CitedMemoryAsset {
            asset_id: chunk.asset_id.clone(),
            payload_sha256: chunk.payload_sha256_hex(),
            citations,
        });
    }
    Ok(CitedMemoryContext {
        tenant: assembly.tenant().clone(),
        projection_sha256: assembly.projection_sha256_hex(),
        items,
        quote_bytes: resolver.quote_total,
    })
}

struct Resolver<'a, S> {
    catalog: &'a EvidenceCatalog,
    source_bytes: &'a S,
    budget: CitationBudget,
    cache: BTreeMap<SourceId, Vec<u8>>,
    source_total: usize,
    quote_total: usize,
    citation_total: usize,
}
impl<S: SourceBytes> Resolver<'_, S> {
    fn resolve(
        &mut self,
        reference: &MemoryEvidenceRef,
    ) -> Result<VerifiedCitation, ProvenanceError> {
        self.citation_total += 1;
        if self.citation_total > self.budget.max_citations {
            return Err(ProvenanceError::Limit);
        }
        let evidence = self
            .catalog
            .evidence
            .get(&EvidenceId::new(reference.as_str()))
            .ok_or(ProvenanceError::MissingEvidence)?;
        let source = self
            .catalog
            .sources
            .get(&evidence.source)
            .ok_or(ProvenanceError::MissingSource)?;
        let source_hash = sha256_content_hash(
            source
                .content_hash
                .as_deref()
                .ok_or(ProvenanceError::MissingHash)?,
        )?;
        let evidence_hash = sha256_content_hash(
            evidence
                .content_hash
                .as_deref()
                .ok_or(ProvenanceError::MissingHash)?,
        )?;
        if source_hash != evidence_hash {
            return Err(ProvenanceError::ContentMismatch);
        }
        if !self.cache.contains_key(&source.id) {
            if self.cache.len() >= self.budget.max_sources {
                return Err(ProvenanceError::Limit);
            }
            let remaining = self
                .budget
                .max_total_source_bytes
                .saturating_sub(self.source_total);
            let limit = self.budget.max_source_bytes.min(remaining);
            let mut bytes = Vec::new();
            self.source_bytes
                .open(&self.catalog.tenant, source)?
                .take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ProvenanceError::SourceUnavailable)?;
            if bytes.len() > limit {
                return Err(ProvenanceError::Limit);
            }
            if hash(&bytes) != source.content_hash.as_deref().unwrap() {
                return Err(ProvenanceError::ContentMismatch);
            }
            self.source_total += bytes.len();
            self.cache.insert(source.id.clone(), bytes);
        }
        let bytes = &self.cache[&source.id];
        let (start, end) = span(
            evidence
                .locator
                .as_deref()
                .ok_or(ProvenanceError::InvalidSpan)?,
            bytes.len(),
        )?;
        self.quote_total = self
            .quote_total
            .checked_add(end - start)
            .ok_or(ProvenanceError::Limit)?;
        if self.quote_total > self.budget.max_quote_bytes {
            return Err(ProvenanceError::Limit);
        }
        let quote = bytes[start..end].to_vec();
        let quote_hash = hash(&quote);
        Ok(VerifiedCitation {
            reference: reference.clone(),
            evidence: evidence.id.clone(),
            source: source.id.clone(),
            source_locator: source.locator.clone(),
            content_hash: format!("sha256:{source_hash}"),
            start,
            end,
            quote,
            quote_hash,
        })
    }
}

/// Canonical hash spelling emitted by ingestion and extraction.
pub fn sha256_content_hash(value: &str) -> Result<&str, ProvenanceError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(ProvenanceError::InvalidHash)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ProvenanceError::InvalidHash);
    }
    Ok(hex)
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn span(value: &str, length: usize) -> Result<(usize, usize), ProvenanceError> {
    let (a, b) = value
        .strip_prefix("bytes:")
        .and_then(|s| s.split_once('-'))
        .ok_or(ProvenanceError::InvalidSpan)?;
    let start = a
        .parse::<usize>()
        .map_err(|_| ProvenanceError::InvalidSpan)?;
    let end = b
        .parse::<usize>()
        .map_err(|_| ProvenanceError::InvalidSpan)?;
    if a != start.to_string() || b != end.to_string() || start >= end || end > length {
        return Err(ProvenanceError::InvalidSpan);
    }
    Ok((start, end))
}
fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
}

#[cfg(test)]
mod tests;

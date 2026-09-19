//! Strict, optional source resolution for admitted governed context. Source
//! locations are display metadata, never network requests or filesystem paths.
use ccos_enterprise_knowledge_model::SourceRecord;
use ccos_enterprise_knowledge_store::KnowledgeStore;
use ccos_enterprise_memory::provenance::{
    self, CitationBudget, CitedMemoryContext, EvidenceCatalog, ProvenanceError, SourceBytes,
};
use ccos_enterprise_memory::{GovernedMemoryContextAssembly, GovernedMemoryProjection};
use ccos_enterprise_tenancy::TenantId;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub(super) struct ServedEvidence {
    catalog: EvidenceCatalog,
    blobs: TenantBlobs,
}
struct TenantBlobs {
    tenant: TenantId,
    root: PathBuf,
}
impl SourceBytes for TenantBlobs {
    fn open(
        &self,
        tenant: &TenantId,
        source: &SourceRecord,
    ) -> Result<Box<dyn std::io::Read>, ProvenanceError> {
        if tenant != &self.tenant || &source.tenant != tenant {
            return Err(ProvenanceError::TenantMismatch);
        }
        let digest = provenance::sha256_content_hash(
            source
                .content_hash
                .as_deref()
                .ok_or(ProvenanceError::MissingHash)?,
        )?;
        let path = self.root.join(digest);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ProvenanceError::SourceUnavailable)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ProvenanceError::SourceUnavailable);
        }
        let file = File::open(path).map_err(|_| ProvenanceError::SourceUnavailable)?;
        if !file
            .metadata()
            .map_err(|_| ProvenanceError::SourceUnavailable)?
            .is_file()
        {
            return Err(ProvenanceError::SourceUnavailable);
        }
        Ok(Box::new(file))
    }
}
impl ServedEvidence {
    pub(super) fn load(tenant: &str, knowledge: &Path, blobs: &Path) -> Result<Self, String> {
        let tenant = TenantId::validated(tenant).ok_or("invalid evidence tenant")?;
        for root in [knowledge, blobs] {
            let m = fs::symlink_metadata(root).map_err(|_| "evidence root is unavailable")?;
            if !m.is_dir() || m.file_type().is_symlink() {
                return Err("evidence root must be a trusted directory".into());
            }
        }
        let journal = knowledge.join(ccos_enterprise_knowledge_store::JOURNAL_FILE);
        let m = fs::symlink_metadata(journal).map_err(|_| "evidence journal is unavailable")?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err("evidence journal must be a regular file".into());
        }
        let lock_path = knowledge.join(ccos_enterprise_knowledge_store::LOCK_FILE);
        let m =
            fs::symlink_metadata(&lock_path).map_err(|_| "evidence journal lock is unavailable")?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err("evidence journal lock must be a regular file".into());
        }
        let lock = File::open(lock_path).map_err(|_| "evidence journal lock is unavailable")?;
        lock.try_lock_shared()
            .map_err(|_| "evidence journal has an active writer")?;
        let loaded = KnowledgeStore::load_bounded(knowledge, 64 * 1024 * 1024)
            .map_err(|_| "evidence journal replay failed")?;
        if loaded.torn_tail != 0 {
            return Err("evidence journal has an unresolved torn tail".into());
        }
        let state = loaded
            .state
            .tenant(&tenant)
            .ok_or("evidence tenant is absent from knowledge journal")?;
        let catalog = EvidenceCatalog::new(
            tenant.clone(),
            state.sources.values().cloned(),
            state.evidence.values().cloned(),
        )
        .map_err(|e| e.to_string())?;
        let root = fs::canonicalize(blobs).map_err(|_| "source root is unavailable")?;
        Ok(Self {
            catalog,
            blobs: TenantBlobs { tenant, root },
        })
    }
    pub(super) fn cite(
        &self,
        assembly: &GovernedMemoryContextAssembly,
        projection: &GovernedMemoryProjection,
        remaining_bytes: usize,
    ) -> Result<CitedMemoryContext, String> {
        provenance::cite_governed_context(
            assembly,
            projection,
            &self.catalog,
            &self.blobs,
            CitationBudget::bounded(remaining_bytes),
        )
        .map_err(|e| e.to_string())
    }
}

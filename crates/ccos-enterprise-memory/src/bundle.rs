use std::collections::BTreeSet;
use std::fmt;

use ccos_enterprise_tenancy::TenantId;

use crate::{MemoryAssetDescriptor, MemoryAssetId, MemoryGraphError, MemoryLineageGraph};

/// Version of the backend-neutral governed-memory bundle manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBundleVersion {
    V1,
}

/// Opaque content digest supplied and verified by the storage/export layer.
///
/// The memory contract intentionally does not choose a hash algorithm. A
/// serializer, backup layer or provider adapter is responsible for verifying
/// transported payload bytes against this value before import.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryContentDigest(String);

impl MemoryContentDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryBundleError> {
        let value = value.into();
        if value.trim().is_empty() {
            Err(MemoryBundleError::InvalidContentDigest)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque provider identity plus provider-local immutable reference.
///
/// This reference is portability metadata only. It grants no authority and does
/// not bypass CCOS tenancy, policy or recall governance on import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProviderReference {
    provider: String,
    reference: String,
}

impl MemoryProviderReference {
    pub fn new(
        provider: impl Into<String>,
        reference: impl Into<String>,
    ) -> Result<Self, MemoryBundleError> {
        let provider = provider.into();
        let reference = reference.into();
        if provider.trim().is_empty() {
            return Err(MemoryBundleError::InvalidProvider);
        }
        if reference.trim().is_empty() {
            return Err(MemoryBundleError::InvalidProviderReference);
        }
        Ok(Self {
            provider,
            reference,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// One portable manifest entry for an active governed-memory asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBundleEntry {
    descriptor: MemoryAssetDescriptor,
    content_digest: MemoryContentDigest,
    payload_bytes: u64,
    provider: MemoryProviderReference,
}

impl MemoryBundleEntry {
    pub fn new(
        descriptor: MemoryAssetDescriptor,
        content_digest: MemoryContentDigest,
        payload_bytes: u64,
        provider: MemoryProviderReference,
    ) -> Self {
        Self {
            descriptor,
            content_digest,
            payload_bytes,
            provider,
        }
    }

    pub fn descriptor(&self) -> &MemoryAssetDescriptor {
        &self.descriptor
    }

    pub fn content_digest(&self) -> &MemoryContentDigest {
        &self.content_digest
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn provider(&self) -> &MemoryProviderReference {
        &self.provider
    }
}

/// Versioned, tenant-bound manifest for portable active governed memory.
///
/// V1 is deliberately a manifest rather than a wire encoding. It preserves CCOS
/// identity, space, stratum and lineage while leaving byte encoding, encryption,
/// signing and digest verification to the surrounding backup/export layer.
///
/// Every derived asset must carry all of its governed parents in the same
/// manifest. The complete descriptor set is then rebuilt through
/// [`MemoryLineageGraph::from_active_descriptors`], so duplicate identities,
/// unresolved/cyclic lineage and cross-space derivations fail closed. V1 carries
/// active descriptors only; stale or invalidated graph state must never be
/// silently restored as active through this format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBundleManifest {
    version: MemoryBundleVersion,
    tenant: TenantId,
    entries: Vec<MemoryBundleEntry>,
}

impl MemoryBundleManifest {
    pub fn v1(
        tenant: TenantId,
        entries: impl IntoIterator<Item = MemoryBundleEntry>,
    ) -> Result<Self, MemoryBundleError> {
        if tenant.0.trim().is_empty() {
            return Err(MemoryBundleError::InvalidTenant);
        }

        let mut entries: Vec<_> = entries.into_iter().collect();
        if entries.is_empty() {
            return Err(MemoryBundleError::EmptyBundle);
        }
        entries.sort_by(|left, right| left.descriptor.id.cmp(&right.descriptor.id));

        let mut ids = BTreeSet::new();
        for entry in &entries {
            if !ids.insert(entry.descriptor.id.clone()) {
                return Err(MemoryBundleError::DuplicateAsset(
                    entry.descriptor.id.clone(),
                ));
            }
        }

        for entry in &entries {
            for parent in entry.descriptor.lineage.parents() {
                if !ids.contains(parent) {
                    return Err(MemoryBundleError::MissingParent {
                        asset: entry.descriptor.id.clone(),
                        parent: parent.clone(),
                    });
                }
            }
        }

        MemoryLineageGraph::from_active_descriptors(
            entries.iter().map(|entry| entry.descriptor.clone()),
        )
        .map_err(MemoryBundleError::InvalidLineage)?;

        Ok(Self {
            version: MemoryBundleVersion::V1,
            tenant,
            entries,
        })
    }

    pub const fn version(&self) -> MemoryBundleVersion {
        self.version
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn entries(&self) -> &[MemoryBundleEntry] {
        &self.entries
    }

    /// Validate that an import request targets the tenant bound into the bundle.
    pub fn validate_import_target(&self, tenant: &TenantId) -> Result<(), MemoryBundleError> {
        if tenant.0.trim().is_empty() {
            return Err(MemoryBundleError::InvalidTenant);
        }
        if tenant != &self.tenant {
            return Err(MemoryBundleError::TenantMismatch);
        }
        Ok(())
    }

    /// Reconstruct the active lineage metadata represented by this manifest.
    ///
    /// This re-applies graph invariants rather than trusting construction-time
    /// validation, which keeps import boundaries fail-closed if validation rules
    /// are strengthened later.
    pub fn active_lineage_graph(&self) -> Result<MemoryLineageGraph, MemoryBundleError> {
        MemoryLineageGraph::from_active_descriptors(
            self.entries
                .iter()
                .map(|entry| entry.descriptor.clone()),
        )
        .map_err(MemoryBundleError::InvalidLineage)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryBundleError {
    InvalidTenant,
    EmptyBundle,
    InvalidContentDigest,
    InvalidProvider,
    InvalidProviderReference,
    DuplicateAsset(MemoryAssetId),
    MissingParent {
        asset: MemoryAssetId,
        parent: MemoryAssetId,
    },
    InvalidLineage(MemoryGraphError),
    TenantMismatch,
}

impl fmt::Display for MemoryBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTenant => write!(f, "memory bundle tenant must not be empty"),
            Self::EmptyBundle => write!(f, "memory bundle must contain at least one asset"),
            Self::InvalidContentDigest => write!(f, "memory bundle content digest must not be empty"),
            Self::InvalidProvider => write!(f, "memory bundle provider must not be empty"),
            Self::InvalidProviderReference => {
                write!(f, "memory bundle provider reference must not be empty")
            }
            Self::DuplicateAsset(id) => {
                write!(f, "memory bundle contains duplicate asset {}", id.as_str())
            }
            Self::MissingParent { asset, parent } => write!(
                f,
                "memory bundle asset {} is missing parent {}",
                asset.as_str(),
                parent.as_str()
            ),
            Self::InvalidLineage(error) => write!(f, "invalid memory bundle lineage: {error}"),
            Self::TenantMismatch => write!(f, "memory bundle import target tenant does not match"),
        }
    }
}

impl std::error::Error for MemoryBundleError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryEvidenceRef, MemoryLineage, MemorySpace, MemoryStratum};

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    fn root(value: &str, space: MemorySpace) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            space,
            MemoryStratum::Evidence,
            MemoryLineage::root([MemoryEvidenceRef::new(format!("audit:{value}")).unwrap()])
                .unwrap(),
        )
        .unwrap()
    }

    fn derived(
        value: &str,
        space: MemorySpace,
        stratum: MemoryStratum,
        parents: impl IntoIterator<Item = MemoryAssetId>,
    ) -> MemoryAssetDescriptor {
        MemoryAssetDescriptor::new(
            id(value),
            space,
            stratum,
            MemoryLineage::derived(parents, []).unwrap(),
        )
        .unwrap()
    }

    fn entry(descriptor: MemoryAssetDescriptor, reference: &str) -> MemoryBundleEntry {
        MemoryBundleEntry::new(
            descriptor,
            MemoryContentDigest::new("sha256:deadbeef").unwrap(),
            4,
            MemoryProviderReference::new("octasoma", reference).unwrap(),
        )
    }

    #[test]
    fn manifest_is_deterministic_and_preserves_lineage() {
        let space = MemorySpace::project("ccos").unwrap();
        let manifest = MemoryBundleManifest::v1(
            TenantId("tenant-a".into()),
            [
                entry(
                    derived(
                        "mem:episode",
                        space.clone(),
                        MemoryStratum::Episode,
                        [id("mem:root")],
                    ),
                    "item:2",
                ),
                entry(root("mem:root", space), "item:1"),
            ],
        )
        .unwrap();

        assert_eq!(manifest.version(), MemoryBundleVersion::V1);
        assert_eq!(manifest.entries().len(), 2);
        assert_eq!(manifest.entries()[0].descriptor().id.as_str(), "mem:episode");
        assert_eq!(manifest.entries()[1].descriptor().id.as_str(), "mem:root");
        assert_eq!(
            manifest.entries()[0]
                .descriptor()
                .lineage
                .parents()
                .next()
                .unwrap()
                .as_str(),
            "mem:root"
        );
        assert_eq!(manifest.active_lineage_graph().unwrap().len(), 2);
    }

    #[test]
    fn duplicate_asset_ids_fail_closed() {
        assert_eq!(
            MemoryBundleManifest::v1(
                TenantId("tenant-a".into()),
                [
                    entry(root("mem:a", MemorySpace::Tenant), "item:1"),
                    entry(root("mem:a", MemorySpace::Tenant), "item:2"),
                ],
            ),
            Err(MemoryBundleError::DuplicateAsset(id("mem:a")))
        );
    }

    #[test]
    fn derived_asset_cannot_silently_drop_parent_from_bundle() {
        assert_eq!(
            MemoryBundleManifest::v1(
                TenantId("tenant-a".into()),
                [entry(
                    derived(
                        "mem:episode",
                        MemorySpace::Tenant,
                        MemoryStratum::Episode,
                        [id("mem:missing")],
                    ),
                    "item:1",
                )],
            ),
            Err(MemoryBundleError::MissingParent {
                asset: id("mem:episode"),
                parent: id("mem:missing"),
            })
        );
    }

    #[test]
    fn cross_space_lineage_fails_closed_even_when_parent_is_present() {
        let parent = root("mem:root", MemorySpace::team("runtime").unwrap());
        let child = derived(
            "mem:episode",
            MemorySpace::project("ccos").unwrap(),
            MemoryStratum::Episode,
            [id("mem:root")],
        );
        let error = MemoryBundleManifest::v1(
            TenantId("tenant-a".into()),
            [entry(parent, "item:1"), entry(child, "item:2")],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            MemoryBundleError::InvalidLineage(MemoryGraphError::CrossSpaceDerivation { .. })
        ));
    }

    #[test]
    fn import_target_is_tenant_bound() {
        let manifest = MemoryBundleManifest::v1(
            TenantId("tenant-a".into()),
            [entry(root("mem:a", MemorySpace::Tenant), "item:1")],
        )
        .unwrap();
        assert_eq!(
            manifest.validate_import_target(&TenantId("tenant-b".into())),
            Err(MemoryBundleError::TenantMismatch)
        );
        assert_eq!(
            manifest.validate_import_target(&TenantId("tenant-a".into())),
            Ok(())
        );
    }

    #[test]
    fn manifest_metadata_is_non_empty_while_empty_payloads_remain_representable() {
        assert_eq!(
            MemoryContentDigest::new("  "),
            Err(MemoryBundleError::InvalidContentDigest)
        );
        assert_eq!(
            MemoryProviderReference::new("", "item:1"),
            Err(MemoryBundleError::InvalidProvider)
        );
        let entry = MemoryBundleEntry::new(
            root("mem:a", MemorySpace::Tenant),
            MemoryContentDigest::new("sha256:x").unwrap(),
            0,
            MemoryProviderReference::new("octasoma", "item:1").unwrap(),
        );
        assert_eq!(entry.payload_bytes(), 0);
    }
}

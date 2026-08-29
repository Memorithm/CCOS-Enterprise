use std::collections::{BTreeMap, BTreeSet};

use ccos_enterprise_memory::{
    GovernedMemoryObservation, GovernedMemoryWrite, GovernedSemanticMemoryProvider,
    LoadoutMemoryQuery, MemoryAssetId, MemoryError, MemorySpace,
};
use ccos_enterprise_tenancy::{TenantId, TenantScope};
use octasoma::HybridMemory;

use super::{validate_embedding, validate_tenant, EnterpriseOctaSoma};

#[derive(Clone)]
struct GovernedRecord {
    asset_id: MemoryAssetId,
    payload: Vec<u8>,
}

pub(super) struct GovernedSpaceMemory {
    index: HybridMemory,
    records: BTreeMap<u64, GovernedRecord>,
    next_token: u64,
}

impl GovernedSpaceMemory {
    fn new(index: HybridMemory) -> Self {
        Self {
            index,
            records: BTreeMap::new(),
            next_token: 1,
        }
    }

    fn insert(
        &mut self,
        asset_id: &MemoryAssetId,
        embedding: &[f32],
        payload: &[u8],
    ) -> Result<(), MemoryError> {
        let token = self.next_token;
        self.next_token = self.next_token.checked_add(1).ok_or(MemoryError::InsertRejected)?;
        let key = token.to_be_bytes();
        if !self.index.insert(embedding, &key) {
            return Err(MemoryError::InsertRejected);
        }
        self.records.insert(
            token,
            GovernedRecord {
                asset_id: asset_id.clone(),
                payload: payload.to_vec(),
            },
        );
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct GovernedTenantMemory {
    pub(super) len: usize,
    asset_ids: BTreeSet<MemoryAssetId>,
    spaces: BTreeMap<MemorySpace, GovernedSpaceMemory>,
}

impl EnterpriseOctaSoma {
    pub fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        inner.space.validate()?;
        validate_embedding(inner.embedding, self.dim)?;

        if self.tenant_len(&tenant) >= self.per_tenant_capacity {
            return Err(MemoryError::TenantCapacityExceeded {
                limit: self.per_tenant_capacity,
            });
        }
        if self
            .governed
            .get(&tenant)
            .is_some_and(|memory| memory.asset_ids.contains(inner.asset_id))
        {
            return Err(MemoryError::InsertRejected);
        }

        let factory = self.factory.clone();
        let tenant_memory = self.governed.entry(tenant).or_default();
        let space_memory = tenant_memory
            .spaces
            .entry(inner.space.clone())
            .or_insert_with(|| GovernedSpaceMemory::new(factory.create()));
        space_memory.insert(inner.asset_id, inner.embedding, inner.payload)?;
        tenant_memory.asset_ids.insert(inner.asset_id.clone());
        tenant_memory.len += 1;
        Ok(())
    }

    pub fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.loadout.is_empty() {
            return Err(MemoryError::EmptyMemoryLoadout);
        }
        for space in inner.loadout.spaces() {
            space.validate()?;
        }
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(tenant_memory) = self.governed.get(&tenant) else {
            return Ok(Vec::new());
        };

        let shortlist = inner.shortlist.max(inner.k).max(1);
        let mut observations = Vec::new();
        for space in inner.loadout.spaces() {
            let Some(memory) = tenant_memory.spaces.get(space) else {
                continue;
            };
            for (encoded_token, similarity) in memory.index.recall(inner.embedding, inner.k, shortlist) {
                let token_bytes: [u8; 8] = encoded_token.try_into().map_err(|_| MemoryError::InsertRejected)?;
                let token = u64::from_be_bytes(token_bytes);
                let record = memory.records.get(&token).ok_or(MemoryError::InsertRejected)?;
                observations.push(GovernedMemoryObservation {
                    asset_id: record.asset_id.clone(),
                    space: space.clone(),
                    payload: record.payload.clone(),
                    similarity,
                });
            }
        }
        observations.sort_by(|left, right| {
            right
                .similarity
                .total_cmp(&left.similarity)
                .then_with(|| left.space.cmp(&right.space))
                .then_with(|| left.asset_id.cmp(&right.asset_id))
        });
        observations.truncate(inner.k);
        Ok(observations)
    }

    pub fn governed_len(&self, tenant: &TenantId) -> usize {
        self.governed.get(tenant).map_or(0, |memory| memory.len)
    }
}

impl GovernedSemanticMemoryProvider for EnterpriseOctaSoma {
    fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), MemoryError> {
        EnterpriseOctaSoma::insert_governed(self, scoped)
    }

    fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, MemoryError> {
        EnterpriseOctaSoma::recall_governed(self, scoped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccos_enterprise_memory::MemoryLoadout;

    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }

    #[test]
    fn governed_recall_preserves_asset_identity_and_payload() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let space = MemorySpace::project("ccos").unwrap();
        let asset = id("memory:7");
        let vector = [1.0, 0.0, 0.0, 0.0];
        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                GovernedMemoryWrite {
                    asset_id: &asset,
                    space: &space,
                    embedding: &vector,
                    payload: b"payload",
                },
            ))
            .unwrap();

        let loadout = MemoryLoadout::new([space.clone()]).unwrap();
        let recalled = memory
            .recall_governed(TenantScope::new(
                tenant,
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 1,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].asset_id, asset);
        assert_eq!(recalled[0].space, space);
        assert_eq!(recalled[0].payload, b"payload");
    }

    #[test]
    fn governed_recall_never_crosses_tenant_or_space() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 7).unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];
        let allowed = MemorySpace::team("runtime").unwrap();
        let excluded = MemorySpace::team("finance").unwrap();
        for (tenant, space, asset, payload) in [
            ("acme", &allowed, "a", b"allowed".as_slice()),
            ("acme", &excluded, "b", b"excluded".as_slice()),
            ("globex", &allowed, "c", b"other-tenant".as_slice()),
        ] {
            let asset_id = id(asset);
            memory
                .insert_governed(TenantScope::new(
                    TenantId(tenant.into()),
                    GovernedMemoryWrite {
                        asset_id: &asset_id,
                        space,
                        embedding: &vector,
                        payload,
                    },
                ))
                .unwrap();
        }
        let loadout = MemoryLoadout::new([allowed.clone()]).unwrap();
        let recalled = memory
            .recall_governed(TenantScope::new(
                TenantId("acme".into()),
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 8,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].payload, b"allowed");
    }

    #[test]
    fn raw_and_governed_entries_share_the_tenant_quota_but_not_indexes() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 2, 9).unwrap();
        let tenant = TenantId("acme".into());
        let vector = [1.0, 0.0, 0.0, 0.0];
        memory
            .insert(TenantScope::new(
                tenant.clone(),
                super::super::MemoryWrite {
                    embedding: &vector,
                    payload: b"raw",
                },
            ))
            .unwrap();
        let asset = id("governed");
        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                GovernedMemoryWrite {
                    asset_id: &asset,
                    space: &MemorySpace::Tenant,
                    embedding: &vector,
                    payload: b"governed",
                },
            ))
            .unwrap();
        assert_eq!(memory.tenant_len(&tenant), 2);
        assert_eq!(memory.governed_len(&tenant), 1);

        let second = id("too-many");
        assert_eq!(
            memory.insert_governed(TenantScope::new(
                tenant,
                GovernedMemoryWrite {
                    asset_id: &second,
                    space: &MemorySpace::Tenant,
                    embedding: &vector,
                    payload: b"overflow",
                },
            )),
            Err(MemoryError::TenantCapacityExceeded { limit: 2 })
        );
    }

    #[test]
    fn duplicate_asset_id_is_rejected_within_tenant() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 11).unwrap();
        let tenant = TenantId("acme".into());
        let vector = [1.0, 0.0, 0.0, 0.0];
        let asset = id("same");
        let first_space = MemorySpace::team("one").unwrap();
        let second_space = MemorySpace::team("two").unwrap();
        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                GovernedMemoryWrite {
                    asset_id: &asset,
                    space: &first_space,
                    embedding: &vector,
                    payload: b"one",
                },
            ))
            .unwrap();
        assert_eq!(
            memory.insert_governed(TenantScope::new(
                tenant,
                GovernedMemoryWrite {
                    asset_id: &asset,
                    space: &second_space,
                    embedding: &vector,
                    payload: b"two",
                },
            )),
            Err(MemoryError::InsertRejected)
        );
    }
}

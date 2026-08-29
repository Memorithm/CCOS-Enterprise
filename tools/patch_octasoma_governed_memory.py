from pathlib import Path

p = Path('crates/ccos-enterprise-octasoma/src/lib.rs')
text = p.read_text()

text = text.replace(
    'use std::collections::BTreeMap;\n',
    'use std::collections::{BTreeMap, BTreeSet};\n',
    1,
)

old_use = '''pub use ccos_enterprise_memory::{
    LoadoutMemoryQuery, MemoryError as EnterpriseMemoryError, MemoryLoadout, MemorySpace,
    ScopedMemoryObservation, ScopedMemoryWrite, SemanticMemoryProvider,
};
'''
new_use = '''pub use ccos_enterprise_memory::{
    GovernedMemoryObservation, GovernedMemoryWrite, GovernedSemanticMemoryProvider,
    LoadoutMemoryQuery, MemoryAssetId, MemoryError as EnterpriseMemoryError, MemoryLoadout,
    MemorySpace, ScopedMemoryObservation, ScopedMemoryWrite, SemanticMemoryProvider,
};
'''
assert old_use in text
text = text.replace(old_use, new_use, 1)

old_tenant = '''#[derive(Default)]
struct TenantMemory {
    len: usize,
    spaces: BTreeMap<MemorySpace, HybridMemory>,
}
'''
new_tenant = '''#[derive(Default)]
struct TenantMemory {
    len: usize,
    spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_ids: BTreeSet<MemoryAssetId>,
}
'''
assert old_tenant in text
text = text.replace(old_tenant, new_tenant, 1)

marker = '''    fn insert_inner(
'''
method = '''    /// Insert a governance-aware observation while preserving its stable asset id.
    ///
    /// Governed observations use indexes distinct from the legacy raw API. This keeps
    /// identity-bearing records unambiguous and prevents arbitrary legacy payload bytes
    /// from being interpreted as metadata envelopes.
    pub fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        inner.space.validate()?;
        validate_embedding(inner.embedding, self.dim)?;

        if self
            .tenants
            .get(&tenant)
            .is_some_and(|memory| memory.len >= self.per_tenant_capacity)
        {
            return Err(EnterpriseMemoryError::TenantCapacityExceeded {
                limit: self.per_tenant_capacity,
            });
        }

        let factory = self.factory.clone();
        let tenant_memory = self.tenants.entry(tenant).or_default();
        if tenant_memory.governed_ids.contains(inner.asset_id) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        let memory = tenant_memory
            .governed_spaces
            .entry(inner.space.clone())
            .or_insert_with(|| factory.create());
        let encoded = encode_governed_payload(inner.asset_id, inner.payload);
        if !memory.insert(inner.embedding, &encoded) {
            return Err(EnterpriseMemoryError::InsertRejected);
        }
        tenant_memory.governed_ids.insert(inner.asset_id.clone());
        tenant_memory.len += 1;
        Ok(())
    }

'''
assert marker in text
text = text.replace(marker, method + marker, 1)

recall_marker = '''    /// Number of memories owned by one tenant across all memory spaces.
'''
recall = '''    /// Recall only identity-bearing governed observations from the explicit loadout.
    pub fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        validate_embedding(inner.embedding, self.dim)?;
        if inner.loadout.is_empty() {
            return Err(EnterpriseMemoryError::EmptyMemoryLoadout);
        }
        for space in inner.loadout.spaces() {
            space.validate()?;
        }
        if inner.k == 0 {
            return Ok(Vec::new());
        }
        let Some(tenant_memory) = self.tenants.get(&tenant) else {
            return Ok(Vec::new());
        };

        let shortlist = inner.shortlist.max(inner.k).max(1);
        let mut observations = Vec::new();
        for space in inner.loadout.spaces() {
            let Some(memory) = tenant_memory.governed_spaces.get(space) else {
                continue;
            };
            for (encoded, similarity) in memory.recall(inner.embedding, inner.k, shortlist) {
                let (asset_id, payload) = decode_governed_payload(encoded).ok_or(
                    EnterpriseMemoryError::InvalidConfiguration("corrupt governed memory payload"),
                )?;
                observations.push(GovernedMemoryObservation {
                    asset_id,
                    space: space.clone(),
                    payload: payload.to_vec(),
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
                .then_with(|| left.payload.cmp(&right.payload))
        });
        observations.truncate(inner.k);
        Ok(observations)
    }

    /// Number of governed memories in one exact tenant/space partition.
    pub fn governed_space_len(&self, tenant: &TenantId, space: &MemorySpace) -> usize {
        self.tenants
            .get(tenant)
            .and_then(|memory| memory.governed_spaces.get(space))
            .map_or(0, HybridMemory::len)
    }

'''
assert recall_marker in text
text = text.replace(recall_marker, recall + recall_marker, 1)

trait_marker = '''fn validate_tenant(tenant: &TenantId) -> Result<(), EnterpriseMemoryError> {
'''
trait_impl = '''impl GovernedSemanticMemoryProvider for EnterpriseOctaSoma {
    fn insert_governed(
        &mut self,
        scoped: TenantScope<GovernedMemoryWrite<'_>>,
    ) -> Result<(), EnterpriseMemoryError> {
        EnterpriseOctaSoma::insert_governed(self, scoped)
    }

    fn recall_governed(
        &self,
        scoped: TenantScope<LoadoutMemoryQuery<'_>>,
    ) -> Result<Vec<GovernedMemoryObservation>, EnterpriseMemoryError> {
        EnterpriseOctaSoma::recall_governed(self, scoped)
    }
}

fn encode_governed_payload(asset_id: &MemoryAssetId, payload: &[u8]) -> Vec<u8> {
    let id = asset_id.as_str().as_bytes();
    let id_len = u32::try_from(id.len()).expect("validated memory asset ids fit in u32");
    let mut encoded = Vec::with_capacity(4 + id.len() + payload.len());
    encoded.extend_from_slice(&id_len.to_be_bytes());
    encoded.extend_from_slice(id);
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_governed_payload(encoded: &[u8]) -> Option<(MemoryAssetId, &[u8])> {
    let header: [u8; 4] = encoded.get(..4)?.try_into().ok()?;
    let id_len = u32::from_be_bytes(header) as usize;
    let id_end = 4usize.checked_add(id_len)?;
    let id = std::str::from_utf8(encoded.get(4..id_end)?).ok()?;
    let asset_id = MemoryAssetId::new(id).ok()?;
    Some((asset_id, encoded.get(id_end..)?))
}

'''
assert trait_marker in text
text = text.replace(trait_marker, trait_impl + trait_marker, 1)

text += r'''

#[cfg(test)]
mod governed_provider_tests {
    use super::*;

    fn governed_write<'a>(
        asset_id: &'a MemoryAssetId,
        space: &'a MemorySpace,
        embedding: &'a [f32],
        payload: &'a [u8],
    ) -> GovernedMemoryWrite<'a> {
        GovernedMemoryWrite {
            asset_id,
            space,
            embedding,
            payload,
        }
    }

    #[test]
    fn governed_recall_preserves_identity_and_space() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let space = MemorySpace::team("runtime").unwrap();
        let id = MemoryAssetId::new("memory:runtime:1").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&id, &space, &vector, b"governed-payload"),
            ))
            .unwrap();

        let loadout = MemoryLoadout::new([space.clone()]).unwrap();
        let recalled = memory
            .recall_governed(TenantScope::new(
                tenant.clone(),
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 4,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();

        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].asset_id, id);
        assert_eq!(recalled[0].space, space);
        assert_eq!(recalled[0].payload, b"governed-payload");
        assert_eq!(memory.governed_space_len(&tenant, &recalled[0].space), 1);
    }

    #[test]
    fn governed_recall_does_not_treat_legacy_payloads_as_identity_envelopes() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let vector = [1.0, 0.0, 0.0, 0.0];
        memory
            .insert(TenantScope::new(
                tenant.clone(),
                MemoryWrite {
                    embedding: &vector,
                    payload: b"legacy",
                },
            ))
            .unwrap();

        let loadout = MemoryLoadout::tenant_only();
        assert!(
            memory
                .recall_governed(TenantScope::new(
                    tenant,
                    LoadoutMemoryQuery {
                        embedding: &vector,
                        k: 4,
                        shortlist: 8,
                        loadout: &loadout,
                    },
                ))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn governed_asset_ids_are_unique_per_tenant() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let first_space = MemorySpace::team("runtime").unwrap();
        let second_space = MemorySpace::project("ccos").unwrap();
        let id = MemoryAssetId::new("memory:unique").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];

        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&id, &first_space, &vector, b"first"),
            ))
            .unwrap();
        assert_eq!(
            memory.insert_governed(TenantScope::new(
                tenant,
                governed_write(&id, &second_space, &vector, b"duplicate"),
            )),
            Err(EnterpriseMemoryError::InsertRejected)
        );
    }

    #[test]
    fn governed_ids_may_repeat_across_tenants() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let space = MemorySpace::Tenant;
        let id = MemoryAssetId::new("memory:tenant-local").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];
        for tenant in ["acme", "globex"] {
            memory
                .insert_governed(TenantScope::new(
                    TenantId(tenant.into()),
                    governed_write(&id, &space, &vector, tenant.as_bytes()),
                ))
                .unwrap();
        }
        assert_eq!(memory.tenant_len(&TenantId("acme".into())), 1);
        assert_eq!(memory.tenant_len(&TenantId("globex".into())), 1);
    }
}
'''

p.write_text(text)

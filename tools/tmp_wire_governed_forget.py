from pathlib import Path

p = Path("crates/ccos-enterprise-octasoma/src/lib.rs")
text = p.read_text()

marker = """#[derive(Debug, Clone, PartialEq)]
pub struct MemoryObservation {
    pub payload: Vec<u8>,
    pub similarity: f32,
}
"""
addition = marker + """
/// Result of an idempotent logical forget operation for governed memory.
///
/// `Forgotten` means the asset became immediately invisible to governed recall.
/// The underlying append-only OctaSoma index is not physically compacted and
/// tenant capacity is therefore not reclaimed by this operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedForgetOutcome {
    Forgotten,
    AlreadyForgotten,
    UnknownAsset,
}
"""
assert marker in text
assert "pub enum GovernedForgetOutcome" not in text
text = text.replace(marker, addition, 1)

marker = """    governed_spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_ids: BTreeSet<MemoryAssetId>,
"""
addition = """    governed_spaces: BTreeMap<MemorySpace, HybridMemory>,
    governed_ids: BTreeSet<MemoryAssetId>,
    forgotten_governed_ids: BTreeSet<MemoryAssetId>,
"""
assert marker in text
text = text.replace(marker, addition, 1)

marker = """    fn insert_inner(
"""
method = """    /// Logically forget one governed asset inside exactly one tenant.
    ///
    /// This operation is deliberately distinct from physical purge. OctaSoma's
    /// `HybridMemory` is append-only, so the encoded bytes remain allocated and
    /// continue to count toward the tenant capacity until a future compactable
    /// backend migration/rebuild. Governed recall filters forgotten identities
    /// before returning observations.
    pub fn forget_governed(
        &mut self,
        scoped: TenantScope<&MemoryAssetId>,
    ) -> Result<GovernedForgetOutcome, EnterpriseMemoryError> {
        let TenantScope { tenant, inner } = scoped;
        validate_tenant(&tenant)?;
        let Some(tenant_memory) = self.tenants.get_mut(&tenant) else {
            return Ok(GovernedForgetOutcome::UnknownAsset);
        };
        if !tenant_memory.governed_ids.contains(inner) {
            return Ok(GovernedForgetOutcome::UnknownAsset);
        }
        if tenant_memory.forgotten_governed_ids.insert(inner.clone()) {
            Ok(GovernedForgetOutcome::Forgotten)
        } else {
            Ok(GovernedForgetOutcome::AlreadyForgotten)
        }
    }

"""
assert marker in text
assert "pub fn forget_governed(" not in text
text = text.replace(marker, method + marker, 1)

marker = """            for (encoded, similarity) in memory.recall(inner.embedding, inner.k, shortlist) {
                let (asset_id, payload) = decode_governed_payload(encoded).ok_or(
                    EnterpriseMemoryError::InvalidConfiguration("corrupt governed memory payload"),
                )?;
                observations.push(GovernedMemoryObservation {
"""
replacement = """            for (encoded, similarity) in memory.recall(inner.embedding, shortlist, shortlist) {
                let (asset_id, payload) = decode_governed_payload(encoded).ok_or(
                    EnterpriseMemoryError::InvalidConfiguration("corrupt governed memory payload"),
                )?;
                if tenant_memory.forgotten_governed_ids.contains(&asset_id) {
                    continue;
                }
                observations.push(GovernedMemoryObservation {
"""
assert marker in text
text = text.replace(marker, replacement, 1)

tests = r'''

    #[test]
    fn governed_forget_hides_asset_and_reveals_next_visible_candidate() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 8, 42).unwrap();
        let tenant = TenantId("acme".into());
        let space = MemorySpace::Tenant;
        let top_id = MemoryAssetId::new("memory:top").unwrap();
        let next_id = MemoryAssetId::new("memory:next").unwrap();
        let top = [1.0, 0.0, 0.0, 0.0];
        let next = [0.8, 0.2, 0.0, 0.0];

        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&top_id, &space, &top, b"top"),
            ))
            .unwrap();
        memory
            .insert_governed(TenantScope::new(
                tenant.clone(),
                governed_write(&next_id, &space, &next, b"next"),
            ))
            .unwrap();
        assert_eq!(
            memory.forget_governed(TenantScope::new(tenant.clone(), &top_id)),
            Ok(GovernedForgetOutcome::Forgotten)
        );

        let loadout = MemoryLoadout::tenant_only();
        let recalled = memory
            .recall_governed(TenantScope::new(
                tenant,
                LoadoutMemoryQuery {
                    embedding: &top,
                    k: 1,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].asset_id, next_id);
        assert_eq!(recalled[0].payload, b"next");
    }

    #[test]
    fn governed_forget_is_tenant_local_idempotent_and_does_not_reclaim_capacity() {
        let mut memory = EnterpriseOctaSoma::new(4, 64, 1, 42).unwrap();
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let space = MemorySpace::Tenant;
        let id = MemoryAssetId::new("memory:shared-id").unwrap();
        let replacement = MemoryAssetId::new("memory:replacement").unwrap();
        let vector = [1.0, 0.0, 0.0, 0.0];

        for tenant in [acme.clone(), globex.clone()] {
            memory
                .insert_governed(TenantScope::new(
                    tenant,
                    governed_write(&id, &space, &vector, b"payload"),
                ))
                .unwrap();
        }

        assert_eq!(
            memory.forget_governed(TenantScope::new(acme.clone(), &id)),
            Ok(GovernedForgetOutcome::Forgotten)
        );
        assert_eq!(
            memory.forget_governed(TenantScope::new(acme.clone(), &id)),
            Ok(GovernedForgetOutcome::AlreadyForgotten)
        );
        assert_eq!(
            memory.forget_governed(TenantScope::new(
                acme.clone(),
                &MemoryAssetId::new("missing").unwrap(),
            )),
            Ok(GovernedForgetOutcome::UnknownAsset)
        );
        assert_eq!(memory.tenant_len(&acme), 1);
        assert_eq!(
            memory.insert_governed(TenantScope::new(
                acme,
                governed_write(&replacement, &space, &vector, b"replacement"),
            )),
            Err(EnterpriseMemoryError::TenantCapacityExceeded { limit: 1 })
        );

        let loadout = MemoryLoadout::tenant_only();
        let globex_hits = memory
            .recall_governed(TenantScope::new(
                globex,
                LoadoutMemoryQuery {
                    embedding: &vector,
                    k: 1,
                    shortlist: 8,
                    loadout: &loadout,
                },
            ))
            .unwrap();
        assert_eq!(globex_hits.len(), 1);
        assert_eq!(globex_hits[0].asset_id, id);
    }
'''
idx = text.rfind("\n}")
assert idx != -1
text = text[:idx] + tests + text[idx:]
p.write_text(text)

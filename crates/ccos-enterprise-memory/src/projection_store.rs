//! Single-owner lifecycle for the version-1 governance projection.
//!
//! This module is a child of `projection`, so encoding and publication reuse the
//! same validating boundary. It stores no embeddings and grants no permissions.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use ccos_enterprise_tenancy::TenantId;

use super::{
    create_projection_root, load_governed_memory_projection, projection_corrupt, projection_io,
    save_governed_memory_projection, sync_directory, GovernedMemoryProjection,
    GovernedMemoryProjectionError, GOVERNED_MEMORY_PROJECTION_FILE,
    MAX_GOVERNED_MEMORY_PROJECTION_BYTES,
};

const LOCK_FILE: &str = ".governed-memory.lock";

/// Failures to open, initialize or update a served governance owner.
#[derive(Debug)]
pub enum GovernedMemoryStoreError {
    Projection(GovernedMemoryProjectionError),
    AlreadyOpen {
        path: PathBuf,
    },
    AlreadyInitialized {
        path: PathBuf,
    },
    MissingProjection {
        path: PathBuf,
    },
    /// Publication was attempted but not acknowledged as durable. Drop and
    /// reopen this owner; neither reads nor another replacement are permitted.
    RecoveryRequired {
        path: PathBuf,
    },
}

impl std::fmt::Display for GovernedMemoryStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Projection(error) => write!(f, "governed memory store: {error}"),
            Self::AlreadyOpen { path } => {
                write!(f, "governed memory store already owned: {path:?}")
            }
            Self::AlreadyInitialized { path } => {
                write!(f, "governed memory projection already exists: {path:?}")
            }
            Self::MissingProjection { path } => {
                write!(f, "governed memory projection required: {path:?}")
            }
            Self::RecoveryRequired { path } => {
                write!(f, "governed memory store must be reopened: {path:?}")
            }
        }
    }
}

impl std::error::Error for GovernedMemoryStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Projection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GovernedMemoryProjectionError> for GovernedMemoryStoreError {
    fn from(error: GovernedMemoryProjectionError) -> Self {
        Self::Projection(error)
    }
}

/// Exclusive, tenant-bound owner of one durable governance projection.
///
/// All cooperating processes must use this owner, not mix it with the low-level
/// save function. The deployment must control the directory and never replace
/// its lock file while an owner is alive. File locking is advisory on some
/// platforms; this is not protection against a malicious filesystem writer.
///
/// Shared borrows expose only the last acknowledged projection. Replacement
/// needs an exclusive borrow and retains the separate lock across atomic file
/// replacements. A publication error removes the in-memory projection so stale
/// authority cannot be read while on-disk publication is uncertain.
///
/// This owner is neither a request authorization token nor a transaction with
/// provider indexes, budget settlement or audit journals. It supplies a
/// prerequisite for that integration, not an operational MCP server by itself.
#[derive(Debug)]
pub struct GovernedMemoryStore {
    root: PathBuf,
    tenant: TenantId,
    projection: Option<GovernedMemoryProjection>,
    _lock: File,
}

impl Drop for GovernedMemoryStore {
    fn drop(&mut self) {
        // Closing only this descriptor can leave the lock held by an
        // inherited descriptor during another thread's fork/exec. The
        // owner exposes no clones; release its lock explicitly first.
        // Drop cannot report errors; descriptor closure is the fallback.
        let _ = self._lock.unlock();
    }
}

impl GovernedMemoryStore {
    /// Open an existing projection for an explicitly selected tenant.
    ///
    /// Missing/corrupt state never initializes empty authority. The lock is held
    /// before reading. The selected file and directory are synced before the
    /// restored state is exposed, including after uncertain prior publication.
    ///
    /// ```no_run
    /// use ccos_enterprise_memory::GovernedMemoryStore;
    /// use ccos_enterprise_tenancy::TenantId;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tenant = TenantId::validated("acme").unwrap();
    /// let store = GovernedMemoryStore::open("/srv/ccos/acme/governance", tenant.clone())?;
    /// let projection = store.projection_for(&tenant)?;
    /// assert_eq!(projection.tenant, tenant);
    /// # Ok(()) }
    /// ```
    pub fn open(
        root: impl AsRef<Path>,
        expected_tenant: TenantId,
    ) -> Result<Self, GovernedMemoryStoreError> {
        validate_tenant(&expected_tenant)?;
        let (root, lock) = lock_directory(root.as_ref(), false)?;
        let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
        let projection = load_governed_memory_projection(&root, Some(&expected_tenant))?
            .ok_or_else(|| GovernedMemoryStoreError::MissingProjection { path: path.clone() })?;
        File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| projection_io(&path, error))?;
        sync_directory(&root).map_err(|error| projection_io(&root, error))?;
        Ok(Self {
            root,
            tenant: expected_tenant,
            projection: Some(projection),
            _lock: lock,
        })
    }

    /// Explicitly provision a new owner; never replace an existing directory entry.
    ///
    /// Even a corrupt file, a directory, or a dangling symlink at the projection
    /// path is an existing entry, not permission to reset authority. Call this
    /// only from an authorized provisioning path, not as a fallback from `open`.
    ///
    /// ```no_run
    /// use ccos_enterprise_memory::{GovernedMemoryProjection, GovernedMemoryStore, GovernedMemoryStoreError};
    /// # fn example(initial: GovernedMemoryProjection) -> Result<(), GovernedMemoryStoreError> {
    /// let store = GovernedMemoryStore::initialize("/srv/ccos/acme/governance", initial)?;
    /// assert!(store.root().is_absolute());
    /// # Ok(()) }
    /// ```
    pub fn initialize(
        root: impl AsRef<Path>,
        initial: GovernedMemoryProjection,
    ) -> Result<Self, GovernedMemoryStoreError> {
        let checked = validate_candidate(&initial.tenant, &initial)?;
        let (root, lock) = lock_directory(root.as_ref(), true)?;
        let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(GovernedMemoryStoreError::AlreadyInitialized { path }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(projection_io(&path, error).into()),
        }
        save_governed_memory_projection(&root, &checked)?;
        Ok(Self {
            root,
            tenant: checked.tenant.clone(),
            projection: Some(checked),
            _lock: lock,
        })
    }

    /// Return the pinned absolute directory, independently of later CWD changes.
    ///
    /// ```no_run
    /// # use ccos_enterprise_memory::GovernedMemoryStore;
    /// # fn example(store: &GovernedMemoryStore) {
    /// assert!(store.root().is_absolute());
    /// # }
    /// ```
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow acknowledged authority only for the caller's explicit tenant.
    ///
    /// This equality check does not authenticate the caller. The server must
    /// obtain `expected_tenant` from its admitted request, never client guesswork.
    ///
    /// ```no_run
    /// # use ccos_enterprise_memory::{GovernedMemoryStore, GovernedMemoryStoreError};
    /// # use ccos_enterprise_tenancy::TenantId;
    /// # fn example(store: &GovernedMemoryStore, tenant: &TenantId) -> Result<(), GovernedMemoryStoreError> {
    /// let active = store.projection_for(tenant)?.graph.active_descriptors();
    /// # let _ = active;
    /// # Ok(()) }
    /// ```
    pub fn projection_for(
        &self,
        expected_tenant: &TenantId,
    ) -> Result<&GovernedMemoryProjection, GovernedMemoryStoreError> {
        let projection = self
            .projection
            .as_ref()
            .ok_or_else(|| self.recovery_error())?;
        check_tenant(&self.tenant, expected_tenant)?;
        Ok(projection)
    }

    /// Validate and durably replace this tenant's projection before exposing it.
    ///
    /// Validation failure preserves the last acknowledged state. Any error after
    /// entering publication poisons this owner, including errors after rename.
    /// Such an error means neither success nor rollback. Drop and explicitly
    /// reopen; no automatic retry of an uncertain governance mutation is made.
    ///
    /// ```no_run
    /// # use ccos_enterprise_memory::{GovernedMemoryStore, GovernedMemoryStoreError, MemoryAssetId};
    /// # use ccos_enterprise_tenancy::TenantId;
    /// # fn example(store: &mut GovernedMemoryStore, tenant: &TenantId, asset: &MemoryAssetId) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut candidate = store.projection_for(tenant)?.clone();
    /// candidate.graph.invalidate(asset)?;
    /// store.replace(candidate)?;
    /// # Ok(()) }
    /// ```
    pub fn replace(
        &mut self,
        candidate: GovernedMemoryProjection,
    ) -> Result<(), GovernedMemoryStoreError> {
        self.replace_with(candidate, save_governed_memory_projection)
    }

    fn recovery_error(&self) -> GovernedMemoryStoreError {
        GovernedMemoryStoreError::RecoveryRequired {
            path: self.root.join(GOVERNED_MEMORY_PROJECTION_FILE),
        }
    }

    fn replace_with(
        &mut self,
        candidate: GovernedMemoryProjection,
        publish: impl FnOnce(
            &Path,
            &GovernedMemoryProjection,
        ) -> Result<PathBuf, GovernedMemoryProjectionError>,
    ) -> Result<(), GovernedMemoryStoreError> {
        if self.projection.is_none() {
            return Err(self.recovery_error());
        }
        let checked = validate_candidate(&self.tenant, &candidate)?;
        self.projection = None;
        publish(&self.root, &checked)?;
        self.projection = Some(checked);
        Ok(())
    }
}

fn validate_tenant(tenant: &TenantId) -> Result<(), GovernedMemoryProjectionError> {
    if TenantId::validated(tenant.as_str()).is_none() {
        return Err(GovernedMemoryProjectionError::TenantInvalid(
            tenant.as_str().to_string(),
        ));
    }
    Ok(())
}

fn check_tenant(
    expected: &TenantId,
    found: &TenantId,
) -> Result<(), GovernedMemoryProjectionError> {
    validate_tenant(expected)?;
    validate_tenant(found)?;
    if expected != found {
        return Err(GovernedMemoryProjectionError::TenantMismatch {
            expected: expected.as_str().to_string(),
            found: found.as_str().to_string(),
        });
    }
    Ok(())
}

fn validate_candidate(
    expected: &TenantId,
    candidate: &GovernedMemoryProjection,
) -> Result<GovernedMemoryProjection, GovernedMemoryProjectionError> {
    check_tenant(expected, &candidate.tenant)?;
    let checked = GovernedMemoryProjection::from_wire(Some(expected), candidate.to_wire())?;
    let encoded = serde_json::to_vec_pretty(&checked.to_wire())
        .map_err(|error| projection_corrupt(&error.to_string()))?;
    if encoded.len() > MAX_GOVERNED_MEMORY_PROJECTION_BYTES {
        return Err(projection_corrupt(
            "projection exceeds the 16 MiB byte limit",
        ));
    }
    Ok(checked)
}

fn lock_directory(root: &Path, create: bool) -> Result<(PathBuf, File), GovernedMemoryStoreError> {
    let root = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    if create {
        create_projection_root(root)?;
    }
    let root = fs::canonicalize(root).map_err(|error| projection_io(root, error))?;
    let path = root.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(&path)
        .map_err(|error| projection_io(&path, error))?;
    lock.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => GovernedMemoryStoreError::AlreadyOpen { path: path.clone() },
        TryLockError::Error(source) => projection_io(&path, source).into(),
    })?;
    // Never remove the lock file on drop: a new inode would split ownership.
    Ok((root, lock))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAssetDescriptor, MemoryAssetId, MemoryAssetState, MemoryEvidenceRef, MemoryLineage,
        MemoryLineageGraph, MemoryLoadoutBinding, MemoryLoadoutPlan, MemorySpace, MemoryStratum,
        MemoryTrustMetadata, MemoryUsageMode,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "ccos-governance-owner-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tenant() -> TenantId {
        TenantId::validated("acme").unwrap()
    }
    fn id(value: &str) -> MemoryAssetId {
        MemoryAssetId::new(value).unwrap()
    }
    fn fixture() -> GovernedMemoryProjection {
        let mut graph = MemoryLineageGraph::new();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("root"),
                    MemorySpace::Tenant,
                    MemoryStratum::Evidence,
                    MemoryLineage::root([MemoryEvidenceRef::new("audit:root").unwrap()]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        graph
            .register(
                MemoryAssetDescriptor::new(
                    id("child"),
                    MemorySpace::Tenant,
                    MemoryStratum::Episode,
                    MemoryLineage::derived([id("root")], []).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        GovernedMemoryProjection::new(
            tenant(),
            graph,
            BTreeMap::from([
                (id("root"), MemoryTrustMetadata::unverified(1)),
                (id("child"), MemoryTrustMetadata::unverified(1)),
            ]),
            MemoryLoadoutPlan::new([MemoryLoadoutBinding::new(
                MemorySpace::Tenant,
                1,
                MemoryUsageMode::Bootstrap,
            )
            .unwrap()])
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn missing_state_never_initializes_implicit_authority() {
        let dir = Directory::new();
        assert!(matches!(
            GovernedMemoryStore::open(&dir.0, tenant()),
            Err(GovernedMemoryStoreError::MissingProjection { .. })
        ));
        assert!(!dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE).exists());
        let absent = dir.0.join("absent");
        assert!(GovernedMemoryStore::open(&absent, tenant()).is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn invalid_tenant_is_rejected_before_creating_files() {
        let dir = Directory::new();
        let root = dir.0.join("invalid");
        let mut initial = fixture();
        initial.tenant = TenantId("../other".into());
        assert!(GovernedMemoryStore::initialize(&root, initial).is_err());
        assert!(GovernedMemoryStore::open(&root, TenantId("../other".into())).is_err());
        assert!(!root.exists());
    }

    #[test]
    fn dropping_owner_releases_duplicated_lock_description() {
        let dir = Directory::new();
        let store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        // A descriptor inherited during a concurrent fork shares this
        // open-file description, even before the child closes it at exec.
        let inherited = store._lock.try_clone().unwrap();
        drop(store);
        let reopened = GovernedMemoryStore::open(&dir.0, tenant()).unwrap();
        drop(inherited);
        assert!(matches!(
            GovernedMemoryStore::open(&dir.0, tenant()),
            Err(GovernedMemoryStoreError::AlreadyOpen { .. })
        ));
        drop(reopened);
    }

    #[test]
    fn second_owner_is_refused_across_replacements_and_released_on_drop() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                GovernedMemoryStore::open(&dir.0, tenant()),
                Err(GovernedMemoryStoreError::AlreadyOpen { .. })
            ));
            assert!(matches!(
                GovernedMemoryStore::initialize(&dir.0, fixture()),
                Err(GovernedMemoryStoreError::AlreadyOpen { .. })
            ));
            store.replace(fixture()).unwrap();
        }
        drop(store);
        assert!(dir.0.join(LOCK_FILE).is_file());
        assert!(GovernedMemoryStore::open(&dir.0, tenant()).is_ok());
    }

    #[test]
    fn corrupt_existing_state_is_neither_opened_nor_overwritten_by_provisioning() {
        let dir = Directory::new();
        let path = dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE);
        fs::write(&path, b"{torn").unwrap();
        assert!(GovernedMemoryStore::open(&dir.0, tenant()).is_err());
        assert!(matches!(
            GovernedMemoryStore::initialize(&dir.0, fixture()),
            Err(GovernedMemoryStoreError::AlreadyInitialized { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), b"{torn");
    }

    #[cfg(unix)]
    #[test]
    fn dangling_projection_symlink_is_an_existing_entry_not_empty_authority() {
        let dir = Directory::new();
        let path = dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE);
        std::os::unix::fs::symlink(dir.0.join("missing-target"), &path).unwrap();
        assert!(matches!(
            GovernedMemoryStore::initialize(&dir.0, fixture()),
            Err(GovernedMemoryStoreError::AlreadyInitialized { .. })
        ));
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn tenant_mismatch_does_not_change_the_acknowledged_snapshot() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let before = fs::read(dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE)).unwrap();
        let other = TenantId::validated("other").unwrap();
        assert!(store.projection_for(&other).is_err());
        let mut candidate = fixture();
        candidate.tenant = other.clone();
        assert!(matches!(
            store.replace(candidate),
            Err(GovernedMemoryStoreError::Projection(
                GovernedMemoryProjectionError::TenantMismatch { .. }
            ))
        ));
        assert_eq!(store.projection_for(&tenant()).unwrap(), &fixture());
        assert_eq!(
            before,
            fs::read(dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE)).unwrap()
        );
        drop(store);
        assert!(matches!(
            GovernedMemoryStore::open(&dir.0, other),
            Err(GovernedMemoryStoreError::Projection(
                GovernedMemoryProjectionError::TenantMismatch { .. }
            ))
        ));
    }

    #[test]
    fn invalid_candidate_leaves_the_owner_usable() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let mut candidate = fixture();
        candidate
            .trust
            .insert(id("unknown"), MemoryTrustMetadata::unverified(1));
        assert!(store.replace(candidate).is_err());
        assert_eq!(store.projection_for(&tenant()).unwrap(), &fixture());
        store.replace(fixture()).unwrap();
    }

    #[test]
    fn invalidation_and_staleness_survive_a_fresh_owner() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let mut candidate = store.projection_for(&tenant()).unwrap().clone();
        candidate.graph.invalidate(&id("root")).unwrap();
        store.replace(candidate.clone()).unwrap();
        drop(store);
        let reopened = GovernedMemoryStore::open(&dir.0, tenant()).unwrap();
        let current = reopened.projection_for(&tenant()).unwrap();
        assert_eq!(current, &candidate);
        assert_eq!(
            current.graph.state(&id("root")),
            Some(MemoryAssetState::Invalidated)
        );
        assert_eq!(
            current.graph.state(&id("child")),
            Some(MemoryAssetState::Stale)
        );
    }

    #[test]
    fn failure_before_publication_blocks_reads_and_further_writes() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let before = fs::read(dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE)).unwrap();
        let result = store.replace_with(fixture(), |root, _| {
            Err(projection_io(
                root,
                io::Error::other("injected write failure"),
            ))
        });
        assert!(result.is_err());
        assert!(matches!(
            store.projection_for(&tenant()),
            Err(GovernedMemoryStoreError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            store.replace(fixture()),
            Err(GovernedMemoryStoreError::RecoveryRequired { .. })
        ));
        assert_eq!(
            before,
            fs::read(dir.0.join(GOVERNED_MEMORY_PROJECTION_FILE)).unwrap()
        );
        drop(store);
        assert!(GovernedMemoryStore::open(&dir.0, tenant()).is_ok());
    }

    #[test]
    fn failure_after_rename_is_uncertain_not_rollback_and_requires_reopen() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let mut candidate = fixture();
        candidate.graph.invalidate(&id("root")).unwrap();
        let result = store.replace_with(candidate.clone(), |root, projection| {
            let path = root.join(GOVERNED_MEMORY_PROJECTION_FILE);
            let bytes = serde_json::to_vec_pretty(&projection.to_wire()).unwrap();
            super::super::publish_projection(root, &path, &bytes, |_| {
                Err(io::Error::other("injected directory sync failure"))
            })?;
            Ok(path)
        });
        assert!(result.is_err());
        assert!(matches!(
            store.projection_for(&tenant()),
            Err(GovernedMemoryStoreError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            store.replace(fixture()),
            Err(GovernedMemoryStoreError::RecoveryRequired { .. })
        ));
        assert_eq!(
            load_governed_memory_projection(&dir.0, Some(&tenant())).unwrap(),
            Some(candidate.clone())
        );
        drop(store);
        let reopened = GovernedMemoryStore::open(&dir.0, tenant()).unwrap();
        assert_eq!(reopened.projection_for(&tenant()).unwrap(), &candidate);
    }

    #[test]
    fn process_lock_probe() {
        let Some(root) = std::env::var_os("CCOS_GOVERNANCE_LOCK_PROBE_ROOT") else {
            return;
        };
        if std::env::var_os("CCOS_GOVERNANCE_LOCK_PROBE_REOPEN").is_some() {
            let store = GovernedMemoryStore::open(PathBuf::from(root), tenant()).unwrap();
            assert_eq!(
                store
                    .projection_for(&tenant())
                    .unwrap()
                    .graph
                    .state(&id("root")),
                Some(MemoryAssetState::Invalidated)
            );
        } else {
            assert!(matches!(
                GovernedMemoryStore::open(PathBuf::from(root), tenant()),
                Err(GovernedMemoryStoreError::AlreadyOpen { .. })
            ));
        }
    }

    #[test]
    fn ownership_is_exclusive_across_processes_and_reopen_replays_disk() {
        let dir = Directory::new();
        let mut store = GovernedMemoryStore::initialize(&dir.0, fixture()).unwrap();
        let run_probe = |reopen: bool| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "projection::store::tests::process_lock_probe",
                    "--nocapture",
                ])
                .env("CCOS_GOVERNANCE_LOCK_PROBE_ROOT", &dir.0)
                .env_remove("CCOS_GOVERNANCE_LOCK_PROBE_REOPEN");
            if reopen {
                command.env("CCOS_GOVERNANCE_LOCK_PROBE_REOPEN", "1");
            }
            let result = command.output().unwrap();
            assert!(
                result.status.success(),
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("1 passed"),
                "child probe must actually run"
            );
        };
        run_probe(false);
        let mut candidate = fixture();
        candidate.graph.invalidate(&id("root")).unwrap();
        store.replace(candidate).unwrap();
        run_probe(false);
        drop(store);
        run_probe(true);
    }
}

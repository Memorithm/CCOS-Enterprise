//! # CCOS Enterprise — one Core session per tenant
//!
//! `ccos_enterprise_mcp::Backend` receives the **verified** tenant on every
//! dispatch, and its documentation says plainly what the type system cannot:
//! *a backend that ignores that argument is unsound, and no type there can
//! stop it.* This crate is the implementation that does not ignore it.
//!
//! Two tenants sharing one `ccos_core::AgentSession` share a memory graph, and
//! tenant isolation is the outermost promise the product makes. So the mapping
//! from tenant to session is the whole security content of this crate, and it
//! is built to be checkable rather than merely intended:
//!
//! * a session is opened under `<root>/<tenant>`, and the tenant is required
//!   to be a canonical identifier
//!   ([`ccos_enterprise_runtime::is_canonical_identifier`]) — the same rule
//!   `Deployment::add_tenant` enforces, so a tenant that exists is a tenant
//!   whose directory name is safe **by construction**. `..`, `/`, a NUL and a
//!   leading `-` cannot reach the filesystem because they cannot be
//!   provisioned;
//! * that check is *also* re-applied here, on every dispatch. Not because the
//!   runtime is untrusted, but because this crate's guarantee must not depend
//!   on which admission path happened to call it. A backend is exactly the
//!   place where "somebody upstream checked" ages badly.
//!
//! ## Lifecycle: bounded, and durable across eviction
//!
//! Sessions are held open and bounded by a capacity, least-recently-used
//! first. Eviction is where a naive cache loses data, so an evicted session is
//! **checkpointed before it is dropped**: Core's own
//! [`AgentSession::checkpoint`] writes the memory snapshot and the op-log
//! sidecar durably, and [`AgentSession::open`] restores both. A tenant that
//! falls out of the cache and comes back sees its memory, not an empty graph.
//!
//! That is asserted rather than assumed — [`TenantSessions`]'s tests fill the
//! cache past its capacity, return to the evicted tenant, and read back what
//! it wrote.
//!
//! ## What this crate does not decide
//!
//! It does not decide *whether* a call is allowed: that is
//! `Deployment::admit`, and this backend is only ever reached by a call it
//! forwarded. It performs no governance of its own, which is deliberate — a
//! second admission policy is a second thing to drift.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use ccos_core::agent_session::AgentSession;
use ccos_enterprise_mcp::Backend;
use ccos_enterprise_runtime::is_canonical_identifier;
use serde_json::{json, Value};

/// How many Core sessions are held open at once by default.
///
/// Each carries a live memory graph, so this is a memory bound, not a
/// correctness one: an evicted tenant is checkpointed and reopens intact.
pub const DEFAULT_SESSION_CAPACITY: usize = 64;

/// Why a session could not be produced or driven.
#[derive(Debug)]
pub enum SessionError {
    /// The tenant id is not one this crate will turn into a path. Only
    /// reachable if a caller bypassed `Deployment::add_tenant`, which enforces
    /// the same rule — and that is exactly why it is re-checked here.
    UnsafeTenantId { tenant: String },
    /// Core refused to open or persist the session.
    Core { tenant: String, detail: String },
    /// Core answered the call with a JSON-RPC error.
    Tool { tool: String, detail: String },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeTenantId { tenant } => write!(
                f,
                "tenant id {tenant:?} is not a canonical identifier, so it will \
                 not be used as a directory name"
            ),
            Self::Core { tenant, detail } => {
                write!(f, "tenant {tenant:?}: core session: {detail}")
            }
            Self::Tool { tool, detail } => write!(f, "tool {tool:?}: {detail}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// One Core session per tenant, bounded and durable across eviction.
pub struct TenantSessions {
    root: PathBuf,
    capacity: usize,
    live: BTreeMap<String, AgentSession>,
    /// Tenants in use order, least-recently-used first.
    lru: VecDeque<String>,
    evictions: u64,
    opens: u64,
}

impl TenantSessions {
    /// Sessions rooted at `root`, holding [`DEFAULT_SESSION_CAPACITY`] open.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self::with_capacity(root, DEFAULT_SESSION_CAPACITY)
    }

    /// Sessions rooted at `root`, holding at most `capacity` open.
    ///
    /// A capacity of zero is refused by clamping to one: a cache that can hold
    /// nothing would checkpoint and reopen on every single call, which is a
    /// performance cliff disguised as a configuration value.
    pub fn with_capacity(root: impl AsRef<Path>, capacity: usize) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            capacity: capacity.max(1),
            live: BTreeMap::new(),
            lru: VecDeque::new(),
            evictions: 0,
            opens: 0,
        }
    }

    /// Where this tenant's memory lives.
    ///
    /// The canonicality check is the reason this returns a `Result`. It is the
    /// only place a tenant id becomes a path, so it is the only place that has
    /// to be right.
    pub fn path_for(&self, tenant: &str) -> Result<PathBuf, SessionError> {
        if !is_canonical_identifier(tenant) {
            return Err(SessionError::UnsafeTenantId {
                tenant: tenant.chars().take(64).collect(),
            });
        }
        Ok(self.root.join(tenant).join("workspace.ccos"))
    }

    /// How many sessions have been evicted, and how many opened.
    ///
    /// An eviction rate close to the call rate means the capacity is too small
    /// for the tenant set, which is a tuning signal an operator cannot get
    /// from anywhere else.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn opens(&self) -> u64 {
        self.opens
    }

    /// Tenants currently held open, in name order.
    pub fn live_tenants(&self) -> Vec<&str> {
        self.live.keys().map(String::as_str).collect()
    }

    fn touch(&mut self, tenant: &str) {
        if let Some(i) = self.lru.iter().position(|t| t == tenant) {
            self.lru.remove(i);
        }
        self.lru.push_back(tenant.to_string());
    }

    /// Evict the least-recently-used session, checkpointing it first.
    ///
    /// The checkpoint is what makes eviction safe. Without it a tenant that
    /// fell out of the cache would come back to an empty memory graph, and the
    /// failure would look like data loss rather than a cache policy.
    fn evict_one(&mut self) -> Result<(), SessionError> {
        let Some(victim) = self.lru.pop_front() else {
            return Ok(());
        };
        if let Some(mut session) = self.live.remove(&victim) {
            checkpoint(&mut session, &victim)?;
        }
        self.evictions += 1;
        Ok(())
    }

    /// The session for `tenant`, opening it if it is not already live.
    pub fn session_for(&mut self, tenant: &str) -> Result<&mut AgentSession, SessionError> {
        let path = self.path_for(tenant)?;
        if !self.live.contains_key(tenant) {
            while self.live.len() >= self.capacity {
                self.evict_one()?;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| SessionError::Core {
                    tenant: tenant.to_string(),
                    detail: e.to_string(),
                })?;
            }
            // `open` restores a previous snapshot and its op-log sidecar, and
            // creates the workspace when there is none — so the first call for
            // a tenant and the millionth take the same path.
            let session = AgentSession::open(&path).map_err(|e| SessionError::Core {
                tenant: tenant.to_string(),
                detail: format!("{e:?}"),
            })?;
            self.live.insert(tenant.to_string(), session);
            self.opens += 1;
        }
        self.touch(tenant);
        Ok(self
            .live
            .get_mut(tenant)
            .expect("just inserted or already present"))
    }

    /// Make every live session durable, without evicting any of them.
    ///
    /// Call this on a clean shutdown, and periodically if the deployment wants
    /// a bounded recovery window. Eviction checkpoints on its own, so this is
    /// about the sessions that are *not* being evicted.
    pub fn checkpoint_all(&mut self) -> Result<(), SessionError> {
        let names: Vec<String> = self.live.keys().cloned().collect();
        for name in names {
            if let Some(session) = self.live.get_mut(&name) {
                checkpoint(session, &name)?;
            }
        }
        Ok(())
    }
}

/// `checkpoint` returns `NoPath` for an in-memory session; every session here
/// is file-backed, so anything else is a real durability failure.
fn checkpoint(session: &mut AgentSession, tenant: &str) -> Result<(), SessionError> {
    session.checkpoint().map_err(|e| SessionError::Core {
        tenant: tenant.to_string(),
        detail: format!("checkpoint: {e:?}"),
    })
}

impl Backend for TenantSessions {
    /// Run `core_tool` in `tenant`'s own session.
    ///
    /// The call goes through Core's own `tools/call` dispatcher rather than a
    /// per-tool `match` here. That is deliberate: a translation table plus a
    /// second dispatcher is two places to drift from Core's catalogue, and
    /// `ccos_enterprise_mcp`'s contract test only guards the first.
    fn dispatch(
        &mut self,
        tenant: &str,
        core_tool: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let session = self.session_for(tenant).map_err(|e| e.to_string())?;
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": core_tool, "arguments": arguments },
        });
        let response = ccos_core::mcp::handle(session, &message)
            .ok_or_else(|| format!("core returned no response for {core_tool:?}"))?;
        if let Some(error) = response.get("error") {
            return Err(format!("core refused {core_tool:?}: {error}"));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("core answered {core_tool:?} with neither result nor error"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ccos-sessions-{tag}-{pid}",
            pid = std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// Core's `ingest` takes a `uri` and a `source`; `recall` with the
    /// `working_set` strategy returns what the session holds. Using Core's
    /// real argument shapes rather than a convenient fiction is the point of
    /// driving the actual dispatcher.
    fn ingest(
        s: &mut TenantSessions,
        tenant: &str,
        uri: &str,
        source: &str,
    ) -> Result<Value, String> {
        s.dispatch(tenant, "ingest", &json!({ "uri": uri, "source": source }))
    }

    fn working_set(s: &mut TenantSessions, tenant: &str) -> Result<Value, String> {
        s.dispatch(
            tenant,
            "recall",
            &json!({ "strategy": "working_set", "budget": 4000 }),
        )
    }

    /// The property the whole crate exists for.
    #[test]
    fn two_tenants_never_share_a_memory_graph() {
        let dir = scratch("isolation");
        let mut s = TenantSessions::new(&dir);

        ingest(
            &mut s,
            "acme",
            "src/falcon.rs",
            "fn falcon() { /* acme only */ }",
        )
        .expect("acme ingests");
        ingest(&mut s, "globex", "src/other.rs", "fn other() {}").expect("globex ingests");

        // Each tenant's own working set sees its own file and not the other's.
        let acme = working_set(&mut s, "acme").expect("acme recalls");
        let globex = working_set(&mut s, "globex").expect("globex recalls");
        let acme_text = acme.to_string();
        let globex_text = globex.to_string();
        assert!(
            acme_text.contains("falcon"),
            "acme cannot see its own file: {acme_text}"
        );
        assert!(
            !globex_text.contains("falcon"),
            "globex saw acme's file: {globex_text}"
        );
        assert!(
            globex_text.contains("other"),
            "globex cannot see its own file: {globex_text}"
        );

        // …and they are physically separate directories.
        assert_ne!(s.path_for("acme").unwrap(), s.path_for("globex").unwrap());
        assert!(dir.join("acme").is_dir());
        assert!(dir.join("globex").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tenant id never becomes a path unless it is safe to.
    ///
    /// `Deployment::add_tenant` already refuses these, so this is defence in
    /// depth — and the depth is the point: this crate's guarantee must not
    /// depend on which caller reached it.
    #[test]
    fn a_hostile_tenant_id_never_reaches_the_filesystem() {
        let dir = scratch("traversal");
        let s = TenantSessions::new(&dir);
        for hostile in [
            "..",
            ".",
            "../../etc",
            "a/b",
            "a\\b",
            "a\u{0}b",
            "-rf",
            "",
            "Acme",
            "acme ",
            "\u{430}cme",
        ] {
            let e = match s.path_for(hostile) {
                Ok(p) => panic!("{hostile:?} produced a path: {}", p.display()),
                Err(e) => e,
            };
            assert!(matches!(e, SessionError::UnsafeTenantId { .. }), "{e}");
        }
        // The canonical one does produce a path, under the root and nowhere else.
        let good = s.path_for("acme").expect("canonical");
        assert!(good.starts_with(&dir), "{}", good.display());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dispatch refuses a hostile id too, not only `path_for` — the trait
    /// method is the surface a caller actually reaches.
    #[test]
    fn dispatch_refuses_a_hostile_tenant_id() {
        let dir = scratch("dispatch-traversal");
        let mut s = TenantSessions::new(&dir);
        let e =
            ingest(&mut s, "../escape", "src/a.rs", "never lands").expect_err("must be refused");
        assert!(e.contains("canonical"), "{e}");
        assert!(s.live_tenants().is_empty(), "no session was opened");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Eviction is a cache policy, not data loss.
    #[test]
    fn an_evicted_tenant_comes_back_with_its_memory_intact() {
        let dir = scratch("eviction");
        let mut s = TenantSessions::with_capacity(&dir, 2);

        ingest(&mut s, "acme", "src/falcon.rs", "fn falcon() {}").expect("ingest");
        // Two more tenants push `acme` out of a two-slot cache.
        ingest(&mut s, "globex", "src/b.rs", "fn b() {}").expect("ingest");
        ingest(&mut s, "initech", "src/c.rs", "fn c() {}").expect("ingest");
        assert!(s.evictions() >= 1, "the cache never evicted anything");
        assert!(
            !s.live_tenants().contains(&"acme"),
            "acme should have been evicted: {:?}",
            s.live_tenants()
        );

        // Coming back reopens from the checkpoint written at eviction.
        let recalled = working_set(&mut s, "acme").expect("acme recalls after eviction");
        assert!(
            recalled.to_string().contains("falcon"),
            "an evicted tenant lost its memory: {recalled}"
        );
        assert!(
            s.opens() >= 4,
            "acme was reopened, not resurrected in place"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The capacity is a real bound, and zero does not mean zero.
    #[test]
    fn the_cache_is_bounded_and_a_zero_capacity_is_clamped() {
        let dir = scratch("bound");
        let mut s = TenantSessions::with_capacity(&dir, 3);
        for i in 0..12 {
            ingest(&mut s, &format!("t-{i:02}"), "src/a.rs", "fn a() {}").expect("ingest");
            assert!(
                s.live_tenants().len() <= 3,
                "the cache grew past its capacity: {:?}",
                s.live_tenants()
            );
        }
        assert_eq!(s.evictions(), 9);

        let mut zero = TenantSessions::with_capacity(&dir, 0);
        ingest(&mut zero, "acme", "src/a.rs", "fn a() {}").expect("a zero capacity still works");
        assert_eq!(zero.live_tenants().len(), 1, "clamped to one, not to none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A clean shutdown persists everything still live.
    #[test]
    fn checkpoint_all_makes_live_sessions_durable_without_evicting_them() {
        let dir = scratch("shutdown");
        let mut s = TenantSessions::with_capacity(&dir, 8);
        ingest(&mut s, "acme", "src/falcon.rs", "fn falcon() {}").expect("ingest");
        ingest(&mut s, "globex", "src/b.rs", "fn b() {}").expect("ingest");
        s.checkpoint_all().expect("checkpoint");
        assert_eq!(s.live_tenants(), vec!["acme", "globex"], "nothing evicted");
        assert_eq!(s.evictions(), 0);
        drop(s);

        // A fresh manager over the same root sees both tenants' memory.
        let mut reopened = TenantSessions::new(&dir);
        let recalled = working_set(&mut reopened, "acme").expect("recall");
        assert!(
            recalled.to_string().contains("falcon"),
            "a checkpointed session did not survive the restart: {recalled}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tool Core does not have is an error, not a silent success.
    #[test]
    fn an_unknown_core_tool_is_reported_rather_than_swallowed() {
        let dir = scratch("unknown");
        let mut s = TenantSessions::new(&dir);
        let e = s
            .dispatch("acme", "no_such_tool", &json!({}))
            .expect_err("core must refuse");
        assert!(e.contains("no_such_tool"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

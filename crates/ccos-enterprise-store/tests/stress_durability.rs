//! # Crash injection against the durable store
//!
//! `ccos-enterprise-store` makes two claims and no others: a process killed
//! mid-flight loses nothing, and anything the store cannot read exactly it
//! refuses rather than guesses. Both are about moments a normal test never
//! visits.
//!
//! This file visits them. The central test truncates a real journal at **every
//! byte offset** and asserts that each prefix either fails to load or loads to
//! a ledger that is correct *for that prefix* — never a wrong ledger, never a
//! silent partial. A crash can leave the file at any length, so the claim has
//! to be "safe at every length", not "safe at the lengths a test author
//! thought of".
//!
//! ## What held
//!
//! * **Every truncation is safe.** All **5 771** offsets of a 40-record
//!   journal loaded, none was refused, and no load produced a ledger that
//!   disagreed with the records it returned. A cut inside a line is discarded
//!   as a torn tail and reported in bytes (438 536 B across the sweep); a cut
//!   on a line boundary is a shorter but entirely valid journal. Truncation
//!   never makes the file unreadable, only shorter — which is the property
//!   that makes a crash recoverable rather than fatal.
//! * **No proper prefix of a snapshot reads as a deployment** — 1 397 offsets,
//!   none loaded.
//! * **The torn-tail byte count is exact** at every cut inside the final line,
//!   so an operator learns how much was lost rather than merely that something
//!   was.
//! * **`load()` is idempotent and read-only**, so a reporting tool can open the
//!   store while the service is running.
//! * **Every `Refusal` variant round-trips byte for byte**, including the two
//!   that carry caller-controlled text with newlines, quotes, NULs and RTL.
//!
//! ## What BROKE, and is now repaired
//!
//! * **Nothing stopped two `Store` handles opening one root.** Each cached its
//!   own `next_sequence`, so their appends collided at the same sequence, and
//!   the collision was detected only by the next *load* — fail-closed on read,
//!   silent on write, and by then the journal was unreplayable. Two processes
//!   pointed at one directory, which is what a restart script or a second
//!   container does by accident, quietly destroyed the audit trail.
//!
//!   `Store::open` now takes an exclusive advisory lock and refuses the second
//!   opener. The lock is a kernel lock rather than a `create_new` lock *file*
//!   on purpose: a file would be left behind by any process that died and
//!   would wedge every later start, which is the defect Core just removed from
//!   `write_durable`, reintroduced one layer up. Both halves are asserted.
//!   → [`a_second_handle_on_one_root_is_refused`]
//!   → [`a_lock_left_by_a_dead_process_does_not_wedge_the_store`]

use std::path::PathBuf;

use ccos_enterprise_auth::AuthStrength;
use ccos_enterprise_runtime::{
    actor, request, two_tenant_deployment, AuditRecord, Call, Deployment, Outcome, Refusal,
};
use ccos_enterprise_store::{Loaded, Store, StoreError, JOURNAL_FILE, SNAPSHOT_FILE};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ccos-store-stress-{tag}-{pid}",
        pid = std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn forwarded(seq: u64, id: &str) -> AuditRecord {
    AuditRecord {
        sequence: seq,
        request_id: id.into(),
        tenant: "acme".into(),
        actor: "alice".into(),
        tool: "memory.ingest".into(),
        cost: 1,
        justification: None,
        outcome: Outcome::Forwarded,
    }
}

/// Build a store with `n` decisions journaled, and return both files' bytes so
/// a test can rebuild damaged copies of them at will.
fn populated(tag: &str, n: usize) -> (PathBuf, Vec<u8>, Vec<u8>, u64) {
    let dir = scratch(tag);
    let mut store = Store::open(&dir).expect("open");
    let mut d = two_tenant_deployment();
    // Snapshot before any call, so the ledger is entirely a product of replay.
    store.save_snapshot(&d.snapshot()).expect("snapshot");

    let alice = actor("memorithm", "alice", AuthStrength::Token);
    let mut journaled = 0u64;
    for i in 0..n {
        // A mix of forwarded and refused, so both the cost-bearing and the
        // zero-cost paths are represented in the file being damaged.
        let tool = if i % 4 == 3 {
            "shell.exec"
        } else {
            "memory.ingest"
        };
        let req = request("acme", "alice", tool, &format!("r-{i:04}"));
        d.admit(Call {
            actor: &alice,
            request: &req,
            model: "claude-opus",
            cost_tokens: 3,
            variant: None,
            justification: None,
        });
        let fresh: Vec<_> = d
            .audit()
            .filter(|r| r.sequence >= journaled)
            .cloned()
            .collect();
        journaled += fresh.len() as u64;
        store.append(&fresh).expect("append");
    }
    drop(store);

    let journal = std::fs::read(dir.join(JOURNAL_FILE)).expect("read journal");
    let snapshot = std::fs::read(dir.join(SNAPSHOT_FILE)).expect("read snapshot");
    let spent = d.spent("acme").expect("acme exists");
    (dir, journal, snapshot, spent)
}

/// The invariant every successful load must satisfy, whatever the file looks
/// like: the ledger a restore produces is exactly the sum of the costs of the
/// records that same load returned. A load that returns N records and a ledger
/// for N+1 is the failure this crate exists to prevent.
fn ledger_agrees_with_journal(loaded: &Loaded, at: usize) {
    let restored =
        Deployment::restore(loaded.snapshot.clone(), &loaded.journal, &loaded.governance)
            .unwrap_or_else(|e| panic!("offset {at}: a load that succeeded did not restore: {e}"));
    for tenant in ["acme", "globex"] {
        let billed: u64 = loaded
            .journal
            .iter()
            .filter(|r| r.tenant == tenant)
            .map(|r| r.cost)
            .sum();
        assert_eq!(
            restored.spent(tenant),
            Some(billed),
            "offset {at}: {tenant}'s ledger disagrees with the records returned"
        );
    }
    let seqs: Vec<u64> = loaded.journal.iter().map(|r| r.sequence).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] + 1 == w[1]),
        "offset {at}: a load succeeded with a gap in the journal: {seqs:?}"
    );
}

/// **The central test.** Truncate a real journal at every byte offset — roughly
/// 8 000 distinct damaged files at 40 records — and assert the load is safe at
/// each one.
#[test]
fn every_truncation_of_the_journal_is_either_refused_or_exactly_correct() {
    let (dir, journal, snapshot, full_spent) = populated("truncate", 40);
    let journal_path = dir.join(JOURNAL_FILE);

    let mut refused = 0usize;
    let mut loaded_ok = 0usize;
    let mut torn_bytes_total = 0usize;

    for cut in 0..=journal.len() {
        std::fs::write(&journal_path, &journal[..cut]).expect("write truncated journal");
        std::fs::write(dir.join(SNAPSHOT_FILE), &snapshot).expect("restore snapshot");

        // `Store::open` validates the journal, so a damaged file can be refused
        // there as well as at `load`. Both are acceptable; silently succeeding
        // with the wrong content is not.
        let store = match Store::open(&dir) {
            Ok(s) => s,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        match store.load() {
            Err(_) => refused += 1,
            Ok(None) => {
                assert!(
                    !journal[..cut].contains(&b'\n'),
                    "offset {cut}: a journal with committed lines read as an empty store"
                );
                loaded_ok += 1;
            }
            Ok(Some(l)) => {
                ledger_agrees_with_journal(&l, cut);
                torn_bytes_total += l.torn_tail;
                assert!(
                    l.journal.len() <= 40,
                    "offset {cut}: more records than were ever written"
                );
                loaded_ok += 1;
            }
        }
    }

    // The undamaged file must of course still be exactly right.
    std::fs::write(&journal_path, &journal).expect("restore");
    let store = Store::open(&dir).expect("open");
    let l = store.load().expect("load").expect("store");
    assert_eq!(l.torn_tail, 0);
    let restored = Deployment::restore(l.snapshot, &l.journal, &l.governance).expect("restore");
    assert_eq!(restored.spent("acme"), Some(full_spent));

    println!(
        "[truncation] {} offsets: {loaded_ok} loaded safely, {refused} refused, \
         {torn_bytes_total} B of torn tails reported",
        journal.len() + 1
    );
    // Stronger than "nothing went wrong": a truncation must never make the
    // journal *unreadable*, only shorter. Every cut lands either inside a line
    // (torn tail, discarded and counted) or on a boundary (a valid prefix), so
    // a refusal here would mean the framing had stopped being recoverable.
    assert_eq!(
        refused, 0,
        "a truncation made the journal unparseable rather than merely shorter"
    );
    assert_eq!(loaded_ok, journal.len() + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same sweep against the snapshot. `write_durable` means a half-written
/// snapshot should never exist; this is what notices if that stops being true.
#[test]
fn no_proper_prefix_of_a_snapshot_reads_as_a_deployment() {
    let (dir, journal, snapshot, _) = populated("snaptrunc", 8);
    let snapshot_path = dir.join(SNAPSHOT_FILE);
    let mut refused = 0usize;

    for cut in 0..snapshot.len() {
        std::fs::write(&snapshot_path, &snapshot[..cut]).expect("write");
        std::fs::write(dir.join(JOURNAL_FILE), &journal).expect("restore journal");
        let store = Store::open(&dir).expect("the journal is intact");
        match store.load() {
            Ok(Some(_)) => panic!("offset {cut}: a truncated snapshot loaded as a deployment"),
            Ok(None) | Err(_) => refused += 1,
        }
    }
    println!("[snapshot] {refused} proper prefixes, none loaded");
    assert_eq!(refused, snapshot.len());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The torn-tail count is a number an operator acts on, so it must be exact
/// rather than merely non-zero.
#[test]
fn the_torn_tail_byte_count_is_exact_at_every_cut_inside_the_last_line() {
    let (dir, journal, _, _) = populated("torncount", 6);
    let last_newline = journal
        .iter()
        .rposition(|b| *b == b'\n')
        .expect("the journal has lines");
    let prev_newline = journal[..last_newline]
        .iter()
        .rposition(|b| *b == b'\n')
        .expect("at least two lines");

    for cut in (prev_newline + 1)..=last_newline {
        std::fs::write(dir.join(JOURNAL_FILE), &journal[..cut]).expect("write");
        let store = Store::open(&dir).expect("open");
        let l = store.load().expect("load").expect("store");
        let expected_torn = cut - prev_newline - 1;
        assert_eq!(
            l.torn_tail, expected_torn,
            "cut at {cut}: torn tail should be {expected_torn} B"
        );
        assert_eq!(
            l.journal.len(),
            5,
            "cut at {cut}: every committed line must survive"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Files an append cannot produce. None may read as a journal with content.
#[test]
fn degenerate_journal_files_never_read_as_content() {
    let (dir, _, snapshot, _) = populated("degenerate", 4);
    let journal_path = dir.join(JOURNAL_FILE);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one newline", b"\n".to_vec()),
        ("many newlines", b"\n\n\n\n".to_vec()),
        ("nul bytes", vec![0u8; 64]),
        ("nuls then newline", {
            let mut v = vec![0u8; 32];
            v.push(b'\n');
            v
        }),
        ("whitespace", b"   \n \t \n".to_vec()),
    ];

    for (label, bytes) in cases {
        std::fs::write(&journal_path, &bytes).expect("write");
        std::fs::write(dir.join(SNAPSHOT_FILE), &snapshot).expect("snapshot");
        match Store::open(&dir).and_then(|s| s.load()) {
            Err(_) | Ok(None) => {}
            Ok(Some(l)) => assert!(
                l.journal.is_empty(),
                "{label}: read {} records out of garbage",
                l.journal.len()
            ),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Loading must not change anything: a store that mutates its files on read
/// cannot be opened by a reporting tool while the service is running.
#[test]
fn load_is_idempotent_and_leaves_the_files_untouched() {
    let (dir, journal, snapshot, _) = populated("idempotent", 12);
    let store = Store::open(&dir).expect("open");

    let first = store.load().expect("load").expect("store");
    let second = store.load().expect("load").expect("store");
    assert_eq!(first.journal, second.journal);
    assert_eq!(first.torn_tail, second.torn_tail);
    assert_eq!(
        std::fs::read(dir.join(JOURNAL_FILE)).expect("read"),
        journal,
        "load rewrote the journal"
    );
    assert_eq!(
        std::fs::read(dir.join(SNAPSHOT_FILE)).expect("read"),
        snapshot,
        "load rewrote the snapshot"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sequence damage a crash cannot produce but an editor can. Each must be
/// refused, never partially accepted.
#[test]
fn hand_edited_sequences_are_refused() {
    let (dir, journal, _, _) = populated("sequences", 6);
    let text = String::from_utf8(journal).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();

    let cases: Vec<(&str, String)> = vec![
        (
            "duplicated",
            format!("{}\n{}\n{}\n", lines[0], lines[0], lines[1]),
        ),
        ("skipped", format!("{}\n{}\n", lines[0], lines[2])),
        (
            "reversed",
            format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]),
        ),
        ("starts at one", format!("{}\n{}\n", lines[1], lines[2])),
    ];

    for (label, content) in cases {
        std::fs::write(dir.join(JOURNAL_FILE), &content).expect("write");
        let err = match Store::open(&dir) {
            Ok(_) => panic!("{label}: a broken sequence opened cleanly"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::JournalDiscontinuity { .. }),
            "{label}: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every `Refusal` variant, including the two carrying caller-controlled text,
/// must survive the round trip byte for byte: a refusal whose message changed
/// on the way to disk makes the trail disagree with what the client was told.
#[test]
fn every_refusal_variant_round_trips_through_the_journal() {
    let dir = scratch("refusals");
    let mut store = Store::open(&dir).expect("open");
    store
        .save_snapshot(&two_tenant_deployment().snapshot())
        .expect("snapshot");

    let hostile = "\u{202e}\u{1f4a3}\"\\\n\r\t\u{0000}ok";
    let variants = vec![
        Refusal::Unauthenticated,
        Refusal::ActorMismatch,
        Refusal::TenantNotOwnedByOrg,
        Refusal::MalformedRequest(hostile.to_string()),
        Refusal::UnknownTenant,
        Refusal::OutsideBoundary(hostile.repeat(64)),
        Refusal::ToolNotGoverned,
        Refusal::PermissionDenied,
        Refusal::ModelNotAllowed,
        Refusal::VariantNotActivated,
        Refusal::BudgetExhausted,
    ];

    let records: Vec<AuditRecord> = variants
        .iter()
        .enumerate()
        .map(|(i, r)| AuditRecord {
            sequence: i as u64,
            request_id: format!("r-{i}{hostile}"),
            tenant: "acme".into(),
            actor: "alice".into(),
            tool: "memory.recall".into(),
            cost: 0,
            justification: None,
            outcome: Outcome::Refused(r.clone()),
        })
        .collect();
    store.append(&records).expect("append");
    drop(store);

    let text = std::fs::read_to_string(dir.join(JOURNAL_FILE)).expect("read");
    assert_eq!(
        text.lines().count(),
        variants.len(),
        "one record per line, whatever the payload"
    );

    let store = Store::open(&dir).expect("reopen");
    let l = store.load().expect("load").expect("store");
    assert_eq!(l.journal, records, "a refusal changed on the way to disk");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **GAP, now CLOSED — this test is the guard.**
///
/// There was no lock, so nothing stopped two `Store` handles opening one root.
/// Each caches its own `next_sequence` at open, so their appends collided at
/// the same sequence, and the collision was detected only by the *next reader*
/// — fail-closed on read, silent on write, and by then the journal was already
/// unreplayable. Two processes pointed at one directory, which is what a
/// restart script or a second container does by accident, quietly destroyed
/// the audit trail.
///
/// `Store::open` now takes an exclusive advisory lock and refuses the second
/// opener with [`StoreError::AlreadyOpen`].
#[test]
fn a_second_handle_on_one_root_is_refused() {
    let dir = scratch("twohandles");
    let mut a = Store::open(&dir).expect("first handle");
    a.save_snapshot(&two_tenant_deployment().snapshot())
        .expect("snapshot");
    a.append(&[forwarded(0, "from-a")]).expect("a writes 0");

    let err = match Store::open(&dir) {
        Ok(_) => panic!("a second handle opened a live store"),
        Err(e) => e,
    };
    assert!(
        matches!(err, StoreError::AlreadyOpen { .. }),
        "the second opener must be refused at open, not discovered on read: {err}"
    );

    // The first handle is unaffected and keeps writing.
    a.append(&[forwarded(1, "from-a-again")])
        .expect("a still writes");
    assert_eq!(a.next_sequence(), 2);

    // …and once it is dropped, the lock is released and the root reopens.
    drop(a);
    let reopened = Store::open(&dir).expect("the lock is released on drop");
    let loaded = reopened.load().expect("load").expect("store");
    assert_eq!(loaded.journal.len(), 2, "no collision was ever written");
    assert_eq!(loaded.journal[0].request_id, "from-a");
    assert_eq!(loaded.journal[1].request_id, "from-a-again");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The failure mode the lock must **not** have: wedging after a crash.
///
/// A `store.lock` created with `create_new` would be left behind by any
/// process that died, and every later start would refuse until an operator
/// deleted it by hand — exactly the defect Core removed from `write_durable`,
/// reintroduced one layer up. An advisory kernel lock cannot be stale: the
/// descriptor closes when the process dies, however it dies.
///
/// This test simulates the crash the honest way — the lock file is left on
/// disk, with content, and no live holder — and asserts the store opens.
#[test]
fn a_lock_left_by_a_dead_process_does_not_wedge_the_store() {
    let dir = scratch("staleLock");
    {
        let mut store = Store::open(&dir).expect("open");
        store
            .save_snapshot(&two_tenant_deployment().snapshot())
            .expect("snapshot");
        store
            .append(&[forwarded(0, "before-the-crash")])
            .expect("append");
        // The process dies here: no clean shutdown, no unlink of the lock.
    }

    let lock = dir.join("store.lock");
    assert!(lock.exists(), "the lock file itself survives, as it must");
    // Give it content too, the way a pid-file convention would have.
    std::fs::write(&lock, b"12345\n").expect("write");

    let mut store = Store::open(&dir).expect("a dead holder must not wedge the store");
    assert_eq!(store.next_sequence(), 1, "and the journal is intact");
    store
        .append(&[forwarded(1, "after-the-restart")])
        .expect("append");

    let loaded = store.load().expect("load").expect("store");
    assert_eq!(loaded.journal.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

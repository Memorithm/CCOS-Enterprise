//! The composed backup/restore contract: produce, verify, stage, promote —
//! never mutating live state before the complete backup verifies, and
//! staying fail-closed on any corruption.

use std::path::PathBuf;

use ccos_enterprise_backup::{
    create_backup, promote_staged, stage_restore, verify_backup, BackupManifest, BackupTarget,
    FsBackupTarget, Segment,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ccos-backup-conf-{tag}-{pid}",
        pid = std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn segments() -> Vec<Segment> {
    vec![
        Segment {
            name: "ledger".into(),
            bytes: b"ledger-v1".to_vec(),
        },
        Segment {
            name: "memory-root".into(),
            bytes: b"memory-v1".to_vec(),
        },
        Segment {
            name: "skills".into(),
            bytes: b"skills-v1".to_vec(),
        },
    ]
}

#[test]
fn backup_verify_stage_promote_round_trip() {
    let root = scratch("roundtrip");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(), 1_700_000_000).unwrap();
    // The manifest binds tenant, time, digest and count.
    assert_eq!(manifest.tenant, "acme");
    assert_eq!(manifest.segments, 3);
    assert_eq!(manifest.digest.len(), 64);
    verify_backup(&target, "acme", &manifest).unwrap();

    // Stage into an empty directory; live state is untouched.
    let staging = scratch("staging");
    stage_restore(&target, "acme", &manifest, &staging).unwrap();
    assert!(staging.join("manifest.json").exists());
    assert!(staging.join("ledger").exists());

    // Promote atomically over a live root that holds different content.
    let live = scratch("live");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("ledger"), b"old-live").unwrap();
    promote_staged(&staging, &live).unwrap();
    assert_eq!(
        std::fs::read_to_string(live.join("ledger")).unwrap(),
        "ledger-v1",
        "live state was replaced by the verified backup"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_dir_all(&live);
}

#[test]
fn corrupted_backup_refuses_staging_and_promotion() {
    let root = scratch("corrupt");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
    // Tamper one segment after the fact.
    let path = root.join("acme").join("segments").join("ledger");
    std::fs::write(&path, b"tampered").unwrap();
    assert!(verify_backup(&target, "acme", &manifest).is_err());

    // Staging must refuse before any byte is written.
    let staging = scratch("staging-corrupt");
    assert!(stage_restore(&target, "acme", &manifest, &staging).is_err());
    assert!(!staging.exists(), "staging was touched despite corruption");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&staging);
}

#[test]
fn cross_tenant_material_is_refused() {
    let root = scratch("cross");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
    // A manifest that claims to be acme's but is verified as globex's is
    // refused; and producing a backup for an unsafe tenant id is refused.
    assert!(verify_backup(&target, "globex", &manifest).is_err());
    assert!(create_backup(&target, "../escape", &segments(), 1).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn duplicate_and_unsafe_segments_are_refused_at_production() {
    let root = scratch("unsafe");
    let target = FsBackupTarget::new(&root);
    let dupes = vec![
        Segment {
            name: "a".into(),
            bytes: b"x".to_vec(),
        },
        Segment {
            name: "a".into(),
            bytes: b"x".to_vec(),
        },
    ];
    assert!(create_backup(&target, "acme", &dupes, 1).is_err());
    let traversal = vec![Segment {
        name: "../../etc/passwd".into(),
        bytes: b"x".to_vec(),
    }];
    assert!(create_backup(&target, "acme", &traversal, 1).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn manifest_digest_is_reproducible_offline() {
    let root = scratch("digest");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(), 42).unwrap();
    // Recompute the aggregate from the on-disk segments in canonical order:
    // the same bytes must produce the same manifest digest.
    let mut names = target.list_segments("acme").unwrap();
    names.sort();
    let mut digests = Vec::new();
    for name in &names {
        let bytes = target.read_segment("acme", name).unwrap().unwrap();
        digests.push(ccos_enterprise_backup::segment_digest(&bytes));
    }
    let recomputed = ccos_enterprise_backup::manifest_digest(&digests);
    assert_eq!(recomputed, manifest.digest);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn future_schema_manifest_is_refused() {
    let root = scratch("schema");
    let target = FsBackupTarget::new(&root);
    let mut manifest = create_backup(&target, "acme", &segments(), 1).unwrap();
    manifest.schema_version = 999;
    assert!(verify_backup(&target, "acme", &manifest).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn empty_backup_is_refused() {
    let root = scratch("empty");
    let target = FsBackupTarget::new(&root);
    assert!(create_backup(&target, "acme", &[], 1).is_err());
    let manifest = BackupManifest {
        tenant: "acme".into(),
        created_unix: 1,
        digest: "a".repeat(64),
        segments: 0,
        schema_version: 1,
    };
    assert!(verify_backup(&target, "acme", &manifest).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

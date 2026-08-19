//! The composed backup/restore contract: immutable generations, authenticated
//! segment identities, exact-byte staging and atomic live-pointer promotion.

use std::path::PathBuf;

use ccos_enterprise_backup::{
    create_backup, manifest_digest_v2, promote_staged, stage_restore, verify_backup, BackupError,
    BackupManifest, BackupTarget, FsBackupTarget, Segment, BACKUP_SCHEMA,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ccos-backup-conf-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn segments(version: u8) -> Vec<Segment> {
    vec![
        Segment {
            name: "ledger".into(),
            bytes: format!("ledger-v{version}").into_bytes(),
        },
        Segment {
            name: "memory-root".into(),
            bytes: format!("memory-v{version}").into_bytes(),
        },
        Segment {
            name: "skills".into(),
            bytes: format!("skills-v{version}").into_bytes(),
        },
    ]
}

#[test]
fn backup_verify_stage_promote_round_trip() {
    let root = scratch("roundtrip");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(1), 1_700_000_000).unwrap();
    assert_eq!(manifest.tenant, "acme");
    assert_eq!(manifest.segments, 3);
    assert_eq!(manifest.schema_version, BACKUP_SCHEMA);
    verify_backup(&target, "acme", &manifest).unwrap();

    let parent = scratch("live-parent");
    std::fs::create_dir_all(&parent).unwrap();
    let staging = parent.join("stage");
    let live = parent.join("live");
    stage_restore(&target, "acme", &manifest, &staging).unwrap();
    assert!(staging.join("manifest.json").exists());
    assert!(staging.join("segments").join("ledger").exists());
    promote_staged(&staging, &live).unwrap();
    #[cfg(unix)]
    assert!(std::fs::symlink_metadata(&live).unwrap().file_type().is_symlink());
    assert_eq!(
        std::fs::read_to_string(live.join("segments").join("ledger")).unwrap(),
        "ledger-v1"
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(parent);
}

#[test]
fn new_backup_never_mutates_last_known_good_generation() {
    let root = scratch("immutable");
    let target = FsBackupTarget::new(&root);
    let first = create_backup(&target, "acme", &segments(1), 1).unwrap();
    let first_dir = target.current_generation_dir("acme").unwrap().unwrap();
    let old_bytes = std::fs::read(first_dir.join("segments").join("ledger")).unwrap();
    let second = create_backup(&target, "acme", &segments(2), 2).unwrap();
    assert_ne!(first.digest, second.digest);
    assert_eq!(
        std::fs::read(first_dir.join("segments").join("ledger")).unwrap(),
        old_bytes
    );
    assert_eq!(
        target.read_segment("acme", "ledger").unwrap().unwrap(),
        b"ledger-v2"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn schema_v2_authenticates_segment_names_as_well_as_bytes() {
    let original = vec![Segment {
        name: "ledger".into(),
        bytes: b"same".to_vec(),
    }];
    let renamed = vec![Segment {
        name: "other".into(),
        bytes: b"same".to_vec(),
    }];
    assert_ne!(manifest_digest_v2(&original), manifest_digest_v2(&renamed));

    let root = scratch("rename");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
    let dir = target.current_generation_dir("acme").unwrap().unwrap();
    std::fs::rename(
        dir.join("segments").join("ledger"),
        dir.join("segments").join("ledger-renamed"),
    )
    .unwrap();
    assert!(matches!(
        verify_backup(&target, "acme", &manifest),
        Err(BackupError::DigestMismatch { .. })
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn corrupted_backup_refuses_staging_before_touching_destination() {
    let root = scratch("corrupt");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
    let dir = target.current_generation_dir("acme").unwrap().unwrap();
    std::fs::write(dir.join("segments").join("ledger"), b"tampered").unwrap();
    assert!(verify_backup(&target, "acme", &manifest).is_err());
    let staging = scratch("staging-corrupt");
    assert!(stage_restore(&target, "acme", &manifest, &staging).is_err());
    assert!(!staging.exists(), "staging was touched despite corruption");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_tenant_and_unsafe_material_is_refused() {
    let root = scratch("cross");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
    assert!(verify_backup(&target, "globex", &manifest).is_err());
    assert!(create_backup(&target, "../escape", &segments(1), 1).is_err());
    let dupes = vec![
        Segment {
            name: "a".into(),
            bytes: b"x".to_vec(),
        },
        Segment {
            name: "a".into(),
            bytes: b"y".to_vec(),
        },
    ];
    assert!(create_backup(&target, "acme", &dupes, 1).is_err());
    let traversal = vec![Segment {
        name: "../../etc/passwd".into(),
        bytes: b"x".to_vec(),
    }];
    assert!(create_backup(&target, "acme", &traversal, 1).is_err());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg(unix)]
fn repeated_promotion_has_no_mutable_directory_gap() {
    let root = scratch("repeat-source");
    let target = FsBackupTarget::new(&root);
    let parent = scratch("repeat-live");
    std::fs::create_dir_all(&parent).unwrap();
    let live = parent.join("live");

    let first = create_backup(&target, "acme", &segments(1), 1).unwrap();
    let stage1 = parent.join("stage1");
    stage_restore(&target, "acme", &first, &stage1).unwrap();
    promote_staged(&stage1, &live).unwrap();
    let old_target = std::fs::read_link(&live).unwrap();

    let second = create_backup(&target, "acme", &segments(2), 2).unwrap();
    let stage2 = parent.join("stage2");
    stage_restore(&target, "acme", &second, &stage2).unwrap();
    promote_staged(&stage2, &live).unwrap();
    assert!(std::fs::symlink_metadata(&live).unwrap().file_type().is_symlink());
    assert!(parent.join(old_target).exists(), "previous generation was destroyed");
    assert_eq!(
        std::fs::read(live.join("segments").join("ledger")).unwrap(),
        b"ledger-v2"
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(parent);
}

#[test]
#[cfg(unix)]
fn legacy_mutable_live_directory_is_refused_fail_closed() {
    let root = scratch("legacy-source");
    let target = FsBackupTarget::new(&root);
    let manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
    let parent = scratch("legacy-parent");
    std::fs::create_dir_all(&parent).unwrap();
    let live = parent.join("live");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("old"), b"old-live").unwrap();
    let stage = parent.join("stage");
    stage_restore(&target, "acme", &manifest, &stage).unwrap();
    assert!(matches!(
        promote_staged(&stage, &live),
        Err(BackupError::UnsafeLiveLayout { .. })
    ));
    assert_eq!(std::fs::read(live.join("old")).unwrap(), b"old-live");
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(parent);
}

#[test]
fn future_and_empty_manifests_are_refused() {
    let root = scratch("schema");
    let target = FsBackupTarget::new(&root);
    let mut manifest = create_backup(&target, "acme", &segments(1), 1).unwrap();
    manifest.schema_version = BACKUP_SCHEMA + 1;
    assert!(verify_backup(&target, "acme", &manifest).is_err());
    assert!(create_backup(&target, "acme", &[], 1).is_err());
    let empty = BackupManifest {
        tenant: "acme".into(),
        created_unix: 1,
        digest: "a".repeat(64),
        segments: 0,
        schema_version: 1,
    };
    assert!(verify_backup(&target, "acme", &empty).is_err());
    let _ = std::fs::remove_dir_all(root);
}
